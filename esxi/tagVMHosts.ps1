[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [Parameter(Mandatory = $true)]
  [ValidateScript({ Test-Path $_ })]
  [string]$CsvPath,

  [switch]$AutoCreate,
  [switch]$RemoveUnlisted,
  [switch]$DryRun,

  [System.Management.Automation.PSCredential]$Credential,

  [string]$LogDir = ".\logs"
)

# ============================================================
# HARD-CODED SETTINGS (edit only here)
# ============================================================

# Only these categories are allowed to be auto-created
$AllowedCategories = @("ENV", "SITE", "OWNER")   # <-- EDIT THIS LIST

# Sleeps (seconds) - hardcoded as requested
$SLEEP_AFTER_CREATE_SEC = 20     # after creating TagCategory or Tag (sync help)
$SLEEP_AFTER_ASSIGN_SEC = 0      # throttle after assignment/removal (0 = disabled)
$SLEEP_BEFORE_PROCESS_VC_SEC = 30 # used ONLY when linked-group sync is needed

# ============================================================
# DryRun wiring
# ============================================================
if ($DryRun) { $WhatIfPreference = $true }

# ============================================================
# Logging helpers
# ============================================================
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
$ts = Get-Date -Format "yyyyMMdd_HHmmss"
$LogFile   = Join-Path $LogDir "vSphereTagAssignment-$ts.log"
$ReportCsv = Join-Path $LogDir "vSphereTagAssignment-$ts.summary.csv"

function Write-Log {
  param(
    [Parameter(Mandatory=$true)][ValidateSet("INFO","WARN","ERROR","DEBUG")]
    [string]$Level,
    [Parameter(Mandatory=$true)][string]$Message
  )
  $line = "{0} [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"), $Level, $Message
  Add-Content -Path $LogFile -Value $line

  switch ($Level) {
    "INFO"  { Write-Host $line -ForegroundColor Cyan }
    "WARN"  { Write-Host $line -ForegroundColor Yellow }
    "ERROR" { Write-Host $line -ForegroundColor Red }
    "DEBUG" { Write-Host $line -ForegroundColor DarkGray }
  }
}

function Sleep-IfNeeded([int]$Seconds, [string]$Reason) {
  if ($Seconds -gt 0) {
    Write-Log INFO "Sleeping ${Seconds}s ($Reason)"
    Start-Sleep -Seconds $Seconds
  }
}

Write-Log INFO "Starting. CsvPath='$CsvPath' AutoCreate=$AutoCreate RemoveUnlisted=$RemoveUnlisted DryRun=$DryRun"
Write-Log INFO "AllowedCategories (hardcoded, create uses uppercase): $($AllowedCategories -join ', ')"
Write-Log INFO "SleepAfterCreateSec=$SLEEP_AFTER_CREATE_SEC SleepAfterAssignSec=$SLEEP_AFTER_ASSIGN_SEC SleepBeforeProcessVcSec=$SLEEP_BEFORE_PROCESS_VC_SEC"
Write-Log INFO "LogFile='$LogFile'"
Write-Log INFO "ReportCsv='$ReportCsv'"

Set-PowerCLIConfiguration -Scope Session -InvalidCertificateAction Ignore -Confirm:$false | Out-Null

# ============================================================
# Load CSV + discover category columns
# ============================================================
$rows = Import-Csv -Path $CsvPath
if (-not $rows -or $rows.Count -eq 0) { throw "CSV is empty." }

$headers = ($rows | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name)
foreach ($req in @("vcenter","host")) {
  if ($headers -notcontains $req) { throw "CSV missing required column '$req'." }
}

$categoryCols = $headers | Where-Object { $_ -notin @("vcenter","host") }
if (-not $categoryCols -or $categoryCols.Count -eq 0) {
  throw "No tag category columns found. Add columns like 'Env','Site','Owner', etc."
}
Write-Log INFO ("Detected category columns (CSV headers): {0}" -f ($categoryCols -join ", "))

function VCKey([string]$vc) { return $vc.Trim().ToLower() }
function Is-AllowedCategory([string]$CategoryUpper) { return $AllowedCategories -contains $CategoryUpper }

if ($AutoCreate) {
  $disallowed = $categoryCols | ForEach-Object { $_.Trim().ToUpper() } | Where-Object { -not (Is-AllowedCategory $_) } | Sort-Object -Unique
  if ($disallowed.Count -gt 0) {
    Write-Log WARN ("CSV contains categories not in AllowedCategories; they will NOT be created: {0}" -f ($disallowed -join ", "))
  }
}

# ============================================================
# Caches
# ============================================================
$catCache  = @{}  # "vc|CATEGORY_UPPER"
$tagCache  = @{}  # "vc|CATEGORY_UPPER|TAG_UPPER"
$hostCache = @{}  # "vc|hostname"

# ============================================================
# Linked mode detection helpers
# ============================================================
function Get-LinkedPartnersLower {
  param([Parameter(Mandatory=$true)]$Server)

  try {
    $client = $Server.GetClient()
    $linked = $client.ConnectivityService.GetLinkedServers()
    if (-not $linked) { return @() }

    return @(
      $linked |
      ForEach-Object { $_[0] } |
      Where-Object { $_ -and $_.Trim() -ne "" } |
      ForEach-Object { $_.Trim().ToLower() } |
      Sort-Object -Unique
    )
  } catch {
    return @()
  }
}

function Build-LinkedGroups {
  param(
    [Parameter(Mandatory=$true)][string[]]$VcLowers,
    [Parameter(Mandatory=$true)]$Adj  # hashtable: vcLower -> neighborLower[]
  )

  $visited = @{}
  $groupOf = @{}     # vcLower -> groupId
  $members = @{}     # groupId -> [string[]]

  foreach ($vc in $VcLowers) {
    if ($visited.ContainsKey($vc)) { continue }

    # BFS component
    $queue = New-Object System.Collections.Generic.Queue[string]
    $queue.Enqueue($vc)
    $visited[$vc] = $true

    $comp = New-Object System.Collections.Generic.List[string]
    while ($queue.Count -gt 0) {
      $x = $queue.Dequeue()
      $comp.Add($x)

      if ($Adj.ContainsKey($x)) {
        foreach ($n in $Adj[$x]) {
          if (-not $visited.ContainsKey($n)) {
            $visited[$n] = $true
            $queue.Enqueue($n)
          }
        }
      }
    }

    # deterministic groupId = lexicographically smallest member
    $groupId = ($comp | Sort-Object)[0]
    $members[$groupId] = @($comp | Sort-Object)
    foreach ($m in $comp) { $groupOf[$m] = $groupId }
  }

  return @{ groupOf = $groupOf; members = $members }
}

# ============================================================
# Case-insensitive lookup to avoid duplicates
# ============================================================
function Get-TagCategoryCaseInsensitive {
  param([Parameter(Mandatory=$true)]$Server, [Parameter(Mandatory=$true)][string]$NameUpper)

  $cat = Get-TagCategory -Name $NameUpper -Server $Server -ErrorAction SilentlyContinue
  if ($cat) { return $cat }

  return (Get-TagCategory -Server $Server -ErrorAction SilentlyContinue |
          Where-Object { $_.Name -ieq $NameUpper } |
          Select-Object -First 1)
}

function Get-TagCaseInsensitiveInCategory {
  param([Parameter(Mandatory=$true)]$Server, [Parameter(Mandatory=$true)]$CategoryObj, [Parameter(Mandatory=$true)][string]$TagUpper)

  $t = Get-Tag -Name $TagUpper -Category $CategoryObj -Server $Server -ErrorAction SilentlyContinue
  if ($t) { return $t }

  return (Get-Tag -Category $CategoryObj -Server $Server -ErrorAction SilentlyContinue |
          Where-Object { $_.Name -ieq $TagUpper } |
          Select-Object -First 1)
}

# ============================================================
# Connect once per vCenter (NO sleep here)
# ============================================================
$vcenters = $rows | Select-Object -ExpandProperty vcenter -Unique | Where-Object { $_ -and $_.Trim() -ne "" }
if (-not $vcenters -or $vcenters.Count -eq 0) { throw "No vcenter values found in CSV." }

foreach ($vc in $vcenters) {
  $vcTrim = $vc.Trim()
  $already = $global:DefaultVIServers | Where-Object { $_.Name -ieq $vcTrim }
  if ($already) {
    Write-Log INFO "Already connected to vCenter '$vcTrim'"
    continue
  }

  Write-Log INFO "Connecting to vCenter '$vcTrim'"
  if ($Credential) {
    Connect-VIServer -Server $vcTrim -Credential $Credential -ErrorAction Stop | Out-Null
  } else {
    Connect-VIServer -Server $vcTrim -ErrorAction Stop | Out-Null
  }
  Write-Log INFO "Connected to '$vcTrim'"
}

# ============================================================
# Build LinkedMap + Linked Groups for only vCenters in CSV
# ============================================================
$CsvVcLowers = @($vcenters | ForEach-Object { VCKey $_ })
$CsvVcSet = @{}
foreach ($v in $CsvVcLowers) { $CsvVcSet[$v] = $true }

# Build adjacency (undirected) among vCenters in CSV list
$Adj = @{}
foreach ($v in $CsvVcLowers) { $Adj[$v] = @() }

foreach ($vc in $vcenters) {
  $vcTrim = $vc.Trim()
  $server = $global:DefaultVIServers | Where-Object { $_.Name -ieq $vcTrim } | Select-Object -First 1
  if (-not $server) { continue }

  $vcLower = VCKey $vcTrim
  $partners = Get-LinkedPartnersLower -Server $server
  $partnersInCsv = @($partners | Where-Object { $CsvVcSet.ContainsKey($_) })

  if ($partnersInCsv.Count -gt 0) {
    Write-Log INFO "Linked Mode partners (in CSV) for '$vcTrim': $($partnersInCsv -join ', ')"
  } else {
    Write-Log INFO "No Linked Mode partners in CSV for '$vcTrim' (treating as standalone group)"
  }

  # undirected edges
  foreach ($p in $partnersInCsv) {
    if (-not ($Adj[$vcLower] -contains $p)) { $Adj[$vcLower] += $p }
    if (-not ($Adj[$p] -contains $vcLower)) { $Adj[$p] += $vcLower }
  }
}

$groupInfo = Build-LinkedGroups -VcLowers $CsvVcLowers -Adj $Adj
$GroupOf = $groupInfo.groupOf     # vcLower -> groupId
$GroupMembers = $groupInfo.members # groupId -> members

foreach ($gid in ($GroupMembers.Keys | Sort-Object)) {
  $mem = $GroupMembers[$gid]
  if ($mem.Count -gt 1) {
    Write-Log INFO "Linked Group '$gid' members: $($mem -join ', ')"
  } else {
    Write-Log INFO "Standalone Group '$gid' member: $($mem[0])"
  }
}

# ============================================================
# Group sync state:
# - increment groupCreateCounter[gid] when any category/tag is CREATED in that group
# - before processing any VC, if counter advanced since last sleep => sleep once
# ============================================================
$groupCreateCounter = @{}  # gid -> int
$groupSleptCounter  = @{}  # gid -> int
foreach ($gid in $GroupMembers.Keys) {
  $groupCreateCounter[$gid] = 0
  $groupSleptCounter[$gid]  = 0
}

function Note-GroupCreate {
  param([Parameter(Mandatory=$true)]$Server)

  $vcLower = VCKey $Server.Name
  if (-not $GroupOf.ContainsKey($vcLower)) { return }

  $gid = $GroupOf[$vcLower]
  $groupCreateCounter[$gid] = [int]$groupCreateCounter[$gid] + 1
}

function Maybe-Sleep-BeforeProcessingVc {
  param([Parameter(Mandatory=$true)][string]$VcName)

  $vcLower = VCKey $VcName
  if (-not $GroupOf.ContainsKey($vcLower)) { return }

  $gid = $GroupOf[$vcLower]
  $created = [int]$groupCreateCounter[$gid]
  $slept   = [int]$groupSleptCounter[$gid]

  # Only sleep if something was created earlier in this group since last sleep,
  # and this group has >1 member (i.e., linked mode group). For standalone, no need.
  $memberCount = $GroupMembers[$gid].Count
  if ($memberCount -le 1) { return }

  if ($created -gt $slept) {
    Sleep-IfNeeded $SLEEP_BEFORE_PROCESS_VC_SEC "linked-group '$gid' had tag/category creation(s); waiting before processing '$VcName' for sync"
    $groupSleptCounter[$gid] = $created
  }
}

# ============================================================
# Tag category/tag create logic (CREATE IN UPPERCASE, USE IT)
# ============================================================
function Get-OrCreate-CategoryUpper {
  param([Parameter(Mandatory=$true)]$Server, [Parameter(Mandatory=$true)][string]$CategoryUpper)

  $vcKey = VCKey $Server.Name
  $k = "$vcKey|$CategoryUpper"
  if ($catCache.ContainsKey($k)) { return $catCache[$k] }

  $cat = Get-TagCategoryCaseInsensitive -Server $Server -NameUpper $CategoryUpper
  if (-not $cat) {
    if (-not $AutoCreate) { return $null }
    if (-not (Is-AllowedCategory $CategoryUpper)) { return $null }

    $msg = "Create TagCategory '$CategoryUpper' (EntityType=VMHost, Cardinality=Single) on $($Server.Name)"
    if ($PSCmdlet.ShouldProcess($Server.Name, $msg)) {
      $cat = New-TagCategory -Name $CategoryUpper -EntityType VMHost -Cardinality Single -Server $Server
      Write-Log INFO "Created category '$CategoryUpper' on $($Server.Name) (Cardinality=Single)"
      Note-GroupCreate -Server $Server
      Sleep-IfNeeded $SLEEP_AFTER_CREATE_SEC "post category create"
    } else {
      Write-Log INFO "DRYRUN Would create category '$CategoryUpper' on $($Server.Name) (Single)"
      $cat = $null
    }
  }

  $catCache[$k] = $cat
  return $cat
}

function Get-OrCreate-TagUpper {
  param([Parameter(Mandatory=$true)]$Server, [Parameter(Mandatory=$true)]$CategoryObj, [Parameter(Mandatory=$true)][string]$TagUpper)

  $vcKey = VCKey $Server.Name
  $k = "$vcKey|$($CategoryObj.Name.ToUpper())|$TagUpper"
  if ($tagCache.ContainsKey($k)) { return $tagCache[$k] }

  $tag = Get-TagCaseInsensitiveInCategory -Server $Server -CategoryObj $CategoryObj -TagUpper $TagUpper
  if (-not $tag) {
    if (-not $AutoCreate) { return $null }
    if (-not (Is-AllowedCategory $CategoryObj.Name.ToUpper())) { return $null }

    $msg = "Create Tag '$TagUpper' in Category '$($CategoryObj.Name)' on $($Server.Name)"
    if ($PSCmdlet.ShouldProcess($Server.Name, $msg)) {
      $tag = New-Tag -Name $TagUpper -Category $CategoryObj -Server $Server
      Write-Log INFO "Created tag '$TagUpper' in category '$($CategoryObj.Name)' on $($Server.Name)"
      Note-GroupCreate -Server $Server
      Sleep-IfNeeded $SLEEP_AFTER_CREATE_SEC "post tag create"
    } else {
      Write-Log INFO "DRYRUN Would create tag '$TagUpper' in category '$($CategoryObj.Name)' on $($Server.Name)"
      $tag = $null
    }
  }

  $tagCache[$k] = $tag
  return $tag
}

# ============================================================
# Process vCenter-by-vCenter (sleep BEFORE processing VC when needed)
# ============================================================
$report = New-Object System.Collections.Generic.List[Object]
$ok=0; $fail=0; $skip=0; $adds=0; $removes=0

$vcOrder = @($vcenters)

for ($i=0; $i -lt $vcOrder.Count; $i++) {
  $vc = $vcOrder[$i].Trim()
  $server = $global:DefaultVIServers | Where-Object { $_.Name -ieq $vc } | Select-Object -First 1
  if (-not $server) { throw "Not connected to '$vc'." }

  # >>> Enhancement: sleep here if this VC is in a linked group where creations happened earlier
  Maybe-Sleep-BeforeProcessingVc -VcName $vc

  Write-Log INFO "=== Processing vCenter: $vc ($($i+1)/$($vcOrder.Count)) ==="

  $vcRows = $rows | Where-Object { $_.vcenter -ieq $vc }

  # Preload hosts for this vCenter
  $hostNames = $vcRows | Select-Object -ExpandProperty host -Unique | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
  foreach ($hn in $hostNames) {
    $hk = "$(VCKey $vc)|$hn".ToLower()
    if ($hostCache.ContainsKey($hk)) { continue }
    try {
      $hostCache[$hk] = Get-VMHost -Name $hn -Server $server -ErrorAction Stop
    } catch {
      Write-Log ERROR "Host lookup failed: vCenter='$vc' host='$hn' :: $($_.Exception.Message)"
    }
  }

  foreach ($r in $vcRows) {
    $hostName = $r.host.Trim()
    $hk = "$(VCKey $vc)|$hostName".ToLower()

    if (-not $hostCache.ContainsKey($hk)) {
      $fail++
      Write-Log ERROR "Host not found: vCenter='$vc' host='$hostName'"
      $report.Add([pscustomobject]@{ vcenter=$vc; host=$hostName; status="FAIL"; adds=0; removes=0; message="Host not found" })
      continue
    }
    $vmhost = $hostCache[$hk]

    # Desired (create/assign uses uppercase)
    $desired = @{}  # CATEGORY_UPPER -> TAG_UPPER
    foreach ($catNameRaw in $categoryCols) {
      $val = $r.$catNameRaw
      if ([string]::IsNullOrWhiteSpace($val)) { continue }

      $catUpper = $catNameRaw.Trim().ToUpper()
      $tagUpper = $val.Trim().ToUpper()
      $desired[$catUpper] = $tagUpper
    }

    if ($desired.Count -eq 0 -and -not $RemoveUnlisted) {
      $skip++
      Write-Log WARN "No desired tags for host '$($vmhost.Name)' on '$vc' (nothing to do)"
      $report.Add([pscustomobject]@{ vcenter=$vc; host=$vmhost.Name; status="SKIP"; adds=0; removes=0; message="No tags in row" })
      continue
    }

    try {
      $currentAssign = @(Get-TagAssignment -Entity $vmhost -Server $server -ErrorAction SilentlyContinue)

      $currentByCat = @{}
      foreach ($a in $currentAssign) {
        $cnUpper = $a.Tag.Category.Name.ToUpper()
        if (-not $currentByCat.ContainsKey($cnUpper)) { $currentByCat[$cnUpper] = New-Object System.Collections.Generic.List[Object] }
        $currentByCat[$cnUpper].Add($a)
      }

      $rowAdds=0; $rowRemoves=0

      foreach ($catUpper in $desired.Keys) {
        $catObj = Get-OrCreate-CategoryUpper -Server $server -CategoryUpper $catUpper
        if (-not $catObj) {
          if ($AutoCreate -and -not (Is-AllowedCategory $catUpper)) {
            throw "Category '$catUpper' is NOT in AllowedCategories; will not create. Allowed: $($AllowedCategories -join ', ')"
          }
          throw "Category '$catUpper' missing (use -AutoCreate to create if allowed)"
        }

        $tagUpper = $desired[$catUpper]
        $tagObj   = Get-OrCreate-TagUpper -Server $server -CategoryObj $catObj -TagUpper $tagUpper
        if (-not $tagObj -and -not $DryRun) {
          throw "Tag '$tagUpper' missing in category '$($catObj.Name)' (use -AutoCreate to create if allowed)"
        }
        if (-not $tagObj -and $DryRun) {
          Write-Log INFO "DRYRUN Would ensure tag exists: $vc | $($vmhost.Name) | $catUpper:$tagUpper"
        }

        $existingInCat = @()
        if ($currentByCat.ContainsKey($catUpper)) { $existingInCat = @($currentByCat[$catUpper]) }

        # Enforce single: remove other tags in same category
        foreach ($a in $existingInCat) {
          if ($a.Tag.Name.ToUpper() -ne $tagUpper) {
            $msg = "Remove (enforce Single) '$catUpper:$($a.Tag.Name)' from host '$($vmhost.Name)' on '$vc'"
            if ($PSCmdlet.ShouldProcess($vmhost.Name, $msg)) {
              Remove-TagAssignment -TagAssignment $a -Confirm:$false -ErrorAction Stop
            }
            Write-Log INFO "DEL  $vc | $($vmhost.Name) | $catUpper:$($a.Tag.Name) (enforce Single)"
            $rowRemoves++; $removes++
            Sleep-IfNeeded $SLEEP_AFTER_ASSIGN_SEC "post tag removal"
          }
        }

        $hasDesired = ($existingInCat | Where-Object { $_.Tag.Name.ToUpper() -eq $tagUpper } | Select-Object -First 1) -ne $null
        if (-not $hasDesired) {
          $msg = "Assign '$catUpper:$tagUpper' to host '$($vmhost.Name)' on '$vc'"
          if ($PSCmdlet.ShouldProcess($vmhost.Name, $msg)) {
            if (-not $DryRun) {
              New-TagAssignment -Tag $tagObj -Entity $vmhost -Server $server -ErrorAction Stop | Out-Null
            }
          }
          Write-Log INFO "ADD  $vc | $($vmhost.Name) | $catUpper:$tagUpper"
          $rowAdds++; $adds++
          Sleep-IfNeeded $SLEEP_AFTER_ASSIGN_SEC "post tag assignment"
        } else {
          Write-Log DEBUG "HAVE $vc | $($vmhost.Name) | $catUpper:$tagUpper"
        }
      }

      if ($RemoveUnlisted) {
        foreach ($catNameRaw in $categoryCols) {
          $catUpper = $catNameRaw.Trim().ToUpper()
          if (-not $currentByCat.ContainsKey($catUpper)) { continue }

          $desiredTagUpper = $null
          if ($desired.ContainsKey($catUpper)) { $desiredTagUpper = $desired[$catUpper] }

          foreach ($a in @($currentByCat[$catUpper])) {
            $curTagUpper = $a.Tag.Name.ToUpper()
            $shouldRemove = $false
            if ([string]::IsNullOrWhiteSpace($desiredTagUpper)) { $shouldRemove = $true }
            elseif ($curTagUpper -ne $desiredTagUpper) { $shouldRemove = $true }

            if ($shouldRemove) {
              $msg = "Remove (RemoveUnlisted) '$catUpper:$($a.Tag.Name)' from host '$($vmhost.Name)' on '$vc'"
              if ($PSCmdlet.ShouldProcess($vmhost.Name, $msg)) {
                Remove-TagAssignment -TagAssignment $a -Confirm:$false -ErrorAction Stop
              }
              Write-Log INFO "DEL  $vc | $($vmhost.Name) | $catUpper:$($a.Tag.Name) (RemoveUnlisted)"
              $rowRemoves++; $removes++
              Sleep-IfNeeded $SLEEP_AFTER_ASSIGN_SEC "post tag removal"
            }
          }
        }
      }

      $ok++
      $report.Add([pscustomobject]@{
        vcenter=$vc; host=$vmhost.Name; status="OK"; adds=$rowAdds; removes=$rowRemoves;
        message=("desired={0}" -f ($desired.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" } -join ";"))
      })
    }
    catch {
      $fail++
      $msg = $_.Exception.Message
      Write-Log ERROR "FAIL $vc | $($vmhost.Name) :: $msg"
      $report.Add([pscustomobject]@{ vcenter=$vc; host=$vmhost.Name; status="FAIL"; adds=0; removes=0; message=$msg })
    }
  }
}

$report | Export-Csv -NoTypeInformation -Path $ReportCsv -Force

Write-Log INFO "Done. OK=$ok FAIL=$fail SKIP=$skip Adds=$adds Removes=$removes"
Write-Log INFO "Summary CSV: $ReportCsv"
Write-Log INFO "Log file   : $LogFile"

param(
    [Parameter(Mandatory = $true)][string]$Pptx,
    [string]$PngDir = "",
    [string]$Pdf = ""
)
# Layout validation with PowerPoint's own text engine (Windows + Office required).
#   * every shape must lie inside the slide
#   * every text frame's laid-out text must fit inside its shape
#   * text-bearing shapes must not overlap (except declared containers)
# Optionally exports one PNG per slide and a PDF.
$ErrorActionPreference = "Stop"
$app = New-Object -ComObject PowerPoint.Application
$problems = New-Object System.Collections.Generic.List[string]
try {
    $pres = $app.Presentations.Open((Resolve-Path $Pptx).Path, -1, 0, 0)
    $W = $pres.PageSetup.SlideWidth; $H = $pres.PageSetup.SlideHeight
    $tol = 1.0   # points
    foreach ($s in $pres.Slides) {
        $n = $s.SlideIndex
        $texty = @()
        foreach ($sh in $s.Shapes) {
            $name = $sh.Name
            if ($sh.Left -lt -$tol -or $sh.Top -lt -$tol -or
                ($sh.Left + $sh.Width) -gt ($W + $tol) -or ($sh.Top + $sh.Height) -gt ($H + $tol)) {
                $problems.Add(("slide {0}: '{1}' outside slide bounds" -f $n, $name))
            }
            # Content must stay clear of the footer band (bottom 0.40 in = 28.8 pt).
            if (($sh.Top + $sh.Height) -gt ($H - 28.8 + $tol)) {
                $problems.Add(("slide {0}: '{1}' intrudes into the footer band" -f $n, $name))
            }
            if ($sh.HasTextFrame -and $sh.TextFrame2.HasText) {
                $tf = $sh.TextFrame2
                $tr = $tf.TextRange
                $availH = $sh.Height - $tf.MarginTop - $tf.MarginBottom
                $availW = $sh.Width - $tf.MarginLeft - $tf.MarginRight
                $over = $tr.BoundHeight - $availH
                $isDiamond = ($sh.Type -eq 1 -and $sh.AutoShapeType -eq 4)
                if ($isDiamond) { $availW = $sh.Width * 0.75 }
                if ($over -gt $tol) {
                    $problems.Add(("slide {0}: '{1}' text overflows by {2:N1} pt (text {3:N1} / box {4:N1})" -f $n, $name, $over, $tr.BoundHeight, $availH))
                }
                # BoundWidth counts the trailing space left at a soft line wrap, so a
                # wrapped paragraph can read a few points wide while every visible glyph
                # is inside the box. Only flag width overruns above 1%.
                if ($tr.BoundWidth -gt ($availW * 1.01 + $tol) -and $tf.WordWrap -eq -1) {
                    $problems.Add(("slide {0}: '{1}' text wider than box ({2:N1} / {3:N1} pt)" -f $n, $name, $tr.BoundWidth, $availW))
                }
                if ($name -notlike "Tier Band*" -and $name -ne "Title") {
                    $texty += $sh
                }
            }
        }
        # Pairwise overlap of text-bearing shapes (containers declared below are exempt).
        $containers = @{ "Discrete-Event Engine" = "Gateway Packet Filter" }
        for ($i = 0; $i -lt $texty.Count; $i++) {
            for ($j = $i + 1; $j -lt $texty.Count; $j++) {
                $a = $texty[$i]; $b = $texty[$j]
                if ($containers[$a.Name] -eq $b.Name -or $containers[$b.Name] -eq $a.Name) { continue }
                $ox = [Math]::Min($a.Left + $a.Width, $b.Left + $b.Width) - [Math]::Max($a.Left, $b.Left)
                $oy = [Math]::Min($a.Top + $a.Height, $b.Top + $b.Height) - [Math]::Max($a.Top, $b.Top)
                if ($ox -gt $tol -and $oy -gt $tol) {
                    $problems.Add(("slide {0}: '{1}' overlaps '{2}' ({3:N0} x {4:N0} pt)" -f $n, $a.Name, $b.Name, $ox, $oy))
                }
            }
        }
    }
    if ($PngDir) {
        New-Item -ItemType Directory -Force -Path $PngDir | Out-Null
        Get-ChildItem $PngDir -Filter "slide-*.png" -ErrorAction SilentlyContinue | Remove-Item -Force
        foreach ($s in $pres.Slides) {
            $s.Export((Join-Path $PngDir ("slide-{0:D2}.png" -f $s.SlideIndex)), "PNG", 1920, 1080)
        }
    }
    if ($Pdf) { $pres.SaveAs($Pdf, 32) }
    $count = $pres.Slides.Count
    $pres.Close()
} finally {
    $app.Quit()
    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($app) | Out-Null
}
"slides: $count"
if ($problems.Count -eq 0) { "LAYOUT OK: no bound, overflow or overlap problems" }
else { "PROBLEMS ($($problems.Count)):"; $problems | ForEach-Object { "  - $_" } }

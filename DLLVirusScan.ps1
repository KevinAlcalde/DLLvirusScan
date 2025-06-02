# DLLVirusScan.ps1
# Script para detectar y desactivar posibles archivos DLL maliciosos en Windows
# Creado: Abril 2025

# Requiere privilegios de administrador para funcionar correctamente
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "Este script requiere privilegios de administrador para funcionar correctamente."
    Write-Warning "Por favor, ejecute PowerShell como administrador e intente nuevamente."
    exit
}

# Función para mostrar el banner del programa
function Show-Banner {
    Write-Host "`n=============================================" -ForegroundColor Cyan
    Write-Host "      ESCÁNER DE VIRUS DLL" -ForegroundColor Cyan
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host "Este script busca archivos DLL potencialmente maliciosos"
    Write-Host "y los desactiva para proteger su sistema."
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host "`n"
}

# Función para verificar si un archivo DLL es potencialmente malicioso
function Test-SuspiciousDLL {
    param (
        [Parameter(Mandatory=$true)]
        [string]$FilePath
    )
    
    $isSuspicious = $false
    $reasons = @()
    
    try {
        # Verificar tamaño del archivo (los virus suelen ser pequeños)
        $fileSize = (Get-Item $FilePath).Length
        if ($fileSize -lt 10KB) {
            $isSuspicious = $true
            $reasons += "Tamaño sospechosamente pequeño ($fileSize bytes)"
        }
        
        # Verificar firma digital
        $signature = Get-AuthenticodeSignature -FilePath $FilePath
        if ($signature.Status -ne "Valid") {
            $isSuspicious = $true
            $reasons += "Sin firma digital válida"
        }
        
        # Verificar ubicación sospechosa
        $suspiciousLocations = @(
            "\\Temp\\", 
            "\\AppData\\Local\\Temp\\", 
            "\\Windows\\Temp\\",
            "\\ProgramData\\Temp\\"
        )
        
        foreach ($location in $suspiciousLocations) {
            if ($FilePath -match $location) {
                $isSuspicious = $true
                $reasons += "Ubicación sospechosa: $location"
                break
            }
        }
        
        # Verificar fecha de creación reciente (últimas 24 horas)
        $creationTime = (Get-Item $FilePath).CreationTime
        if ((Get-Date) - $creationTime -lt (New-TimeSpan -Hours 24)) {
            $isSuspicious = $true
            $reasons += "Creado recientemente: $creationTime"
        }
        
        # Verificar strings sospechosos en el contenido del archivo
        $content = [System.IO.File]::ReadAllBytes($FilePath)
        $contentString = [System.Text.Encoding]::ASCII.GetString($content)
        
        $suspiciousStrings = @(
            "CreateRemoteThread",
            "VirtualAlloc",
            "WriteProcessMemory",
            "ShellExecute",
            "WScript.Shell",
            "cmd.exe /c",
            "powershell -e",
            "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        )
        
        foreach ($string in $suspiciousStrings) {
            if ($contentString -match $string) {
                $isSuspicious = $true
                $reasons += "Contiene string sospechoso: $string"
            }
        }
    }
    catch {
        Write-Warning "Error al analizar $FilePath : $_"
    }
    
    return @{
        IsSuspicious = $isSuspicious
        Reasons = $reasons
    }
}

# Función para desactivar un archivo DLL sospechoso
function Disable-SuspiciousDLL {
    param (
        [Parameter(Mandatory=$true)]
        [string]$FilePath
    )
    
    try {
        # Crear directorio de cuarentena si no existe
        $quarantineDir = "$env:USERPROFILE\DLLQuarantine"
        if (-not (Test-Path $quarantineDir)) {
            New-Item -Path $quarantineDir -ItemType Directory -Force | Out-Null
        }
        
        # Generar nombre único para el archivo en cuarentena
        $fileName = [System.IO.Path]::GetFileName($FilePath)
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $quarantineFile = "$quarantineDir\${fileName}_${timestamp}.quarantine"
        
        # Crear copia de seguridad
        Copy-Item -Path $FilePath -Destination $quarantineFile -Force
        
        # Cambiar extensión del archivo original
        $disabledPath = "$FilePath.disabled"
        Rename-Item -Path $FilePath -NewName $disabledPath -Force
        
        # Registrar acción en el log
        $logEntry = "$(Get-Date) - Desactivado: $FilePath -> $disabledPath (Copia en $quarantineFile)"
        Add-Content -Path "$quarantineDir\quarantine_log.txt" -Value $logEntry
        
        return @{
            Success = $true
            DisabledPath = $disabledPath
            QuarantinePath = $quarantineFile
        }
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

# Función principal para escanear y desactivar DLLs sospechosos
function Start-DLLVirusScan {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ScanPath,
        
        [Parameter(Mandatory=$false)]
        [switch]$DeepScan,
        
        [Parameter(Mandatory=$false)]
        [switch]$AutoDisable,
        
        [Parameter(Mandatory=$false)]
        [switch]$LogOnly
    )
    
    Show-Banner
    
    Write-Host "Iniciando escaneo en: $ScanPath" -ForegroundColor Yellow
    if ($DeepScan) {
        Write-Host "Modo: Escaneo profundo (puede tardar varios minutos)" -ForegroundColor Yellow
    }
    else {
        Write-Host "Modo: Escaneo rápido" -ForegroundColor Yellow
    }
    
    if ($AutoDisable) {
        Write-Host "Desactivación automática: ACTIVADA" -ForegroundColor Red
    }
    else {
        Write-Host "Desactivación automática: DESACTIVADA (solo reporte)" -ForegroundColor Green
    }
    
    Write-Host "`nBuscando archivos DLL..." -ForegroundColor Cyan
    
    # Determinar profundidad de búsqueda
    $searchDepth = if ($DeepScan) { "-Recurse" } else { "" }
    
    # Buscar todos los archivos DLL en la ruta especificada
    $dllFiles = @()
    if ($DeepScan) {
        $dllFiles = Get-ChildItem -Path $ScanPath -Filter "*.dll" -Recurse -ErrorAction SilentlyContinue
    }
    else {
        $dllFiles = Get-ChildItem -Path $ScanPath -Filter "*.dll" -ErrorAction SilentlyContinue
    }
    
    Write-Host "Se encontraron $($dllFiles.Count) archivos DLL para analizar.`n" -ForegroundColor Cyan
    
    $suspiciousCount = 0
    $disabledCount = 0
    $results = @()
    
    # Analizar cada archivo DLL
    foreach ($dll in $dllFiles) {
        Write-Host "Analizando: $($dll.FullName)" -ForegroundColor Gray
        
        $scanResult = Test-SuspiciousDLL -FilePath $dll.FullName
        
        if ($scanResult.IsSuspicious) {
            $suspiciousCount++
            
            Write-Host "  [ALERTA] Archivo DLL sospechoso encontrado!" -ForegroundColor Red
            Write-Host "  Archivo: $($dll.FullName)" -ForegroundColor Red
            Write-Host "  Razones:" -ForegroundColor Red
            foreach ($reason in $scanResult.Reasons) {
                Write-Host "    - $reason" -ForegroundColor Red
            }
            
            $disableResult = $null
            
            if ($AutoDisable -and -not $LogOnly) {
                Write-Host "  Desactivando archivo..." -ForegroundColor Yellow
                $disableResult = Disable-SuspiciousDLL -FilePath $dll.FullName
                
                if ($disableResult.Success) {
                    $disabledCount++
                    Write-Host "  [OK] Archivo desactivado correctamente" -ForegroundColor Green
                    Write-Host "  Archivo desactivado: $($disableResult.DisabledPath)" -ForegroundColor Green
                    Write-Host "  Copia de seguridad: $($disableResult.QuarantinePath)" -ForegroundColor Green
                }
                else {
                    Write-Host "  [ERROR] No se pudo desactivar el archivo: $($disableResult.Error)" -ForegroundColor Red
                }
            }
            elseif (-not $LogOnly) {
                Write-Host "  Para desactivar este archivo, ejecute el script con el parámetro -AutoDisable" -ForegroundColor Yellow
            }
            
            $results += [PSCustomObject]@{
                FilePath = $dll.FullName
                IsSuspicious = $true
                Reasons = $scanResult.Reasons -join ", "
                Disabled = if ($disableResult -ne $null) { $disableResult.Success } else { $false }
                DisabledPath = if ($disableResult -ne $null -and $disableResult.Success) { $disableResult.DisabledPath } else { $null }
                QuarantinePath = if ($disableResult -ne $null -and $disableResult.Success) { $disableResult.QuarantinePath } else { $null }
            }
            
            Write-Host ""
        }
    }
    
    # Mostrar resumen
    Write-Host "`n=============================================" -ForegroundColor Cyan
    Write-Host "RESUMEN DEL ESCANEO" -ForegroundColor Cyan
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host "Total de archivos DLL analizados: $($dllFiles.Count)"
    Write-Host "Archivos DLL sospechosos encontrados: $suspiciousCount" -ForegroundColor $(if ($suspiciousCount -gt 0) { "Red" } else { "Green" })
    Write-Host "Archivos DLL desactivados: $disabledCount" -ForegroundColor $(if ($disabledCount -gt 0) { "Yellow" } else { "Green" })
    Write-Host "=============================================" -ForegroundColor Cyan
    
    # Guardar resultados en un archivo CSV
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportPath = "$env:USERPROFILE\DLLScanReport_$timestamp.csv"
    $results | Export-Csv -Path $reportPath -NoTypeInformation
    
    Write-Host "`nReporte guardado en: $reportPath" -ForegroundColor Green
    
    return @{
        TotalScanned = $dllFiles.Count
        SuspiciousFound = $suspiciousCount
        DisabledCount = $disabledCount
        ReportPath = $reportPath
        Results = $results
    }
}

# Ejemplo de uso del script
# Start-DLLVirusScan -ScanPath "C:\Windows\System32" -DeepScan -AutoDisable

# Instrucciones de uso
if ($MyInvocation.InvocationName -eq $MyInvocation.MyCommand.Name) {
    Write-Host "`n=============================================" -ForegroundColor Yellow
    Write-Host "INSTRUCCIONES DE USO" -ForegroundColor Yellow
    Write-Host "=============================================" -ForegroundColor Yellow
    Write-Host "Para usar este script, ejecute uno de los siguientes comandos:"
    Write-Host ""
    Write-Host "1. Escaneo rápido (solo reporte):"
    Write-Host "   .\DLLVirusScan.ps1 -ScanPath 'C:\Ruta\A\Escanear'" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "2. Escaneo profundo (solo reporte):"
    Write-Host "   .\DLLVirusScan.ps1 -ScanPath 'C:\Ruta\A\Escanear' -DeepScan" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "3. Escaneo rápido con desactivación automática:"
    Write-Host "   .\DLLVirusScan.ps1 -ScanPath 'C:\Ruta\A\Escanear' -AutoDisable" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "4. Escaneo profundo con desactivación automática:"
    Write-Host "   .\DLLVirusScan.ps1 -ScanPath 'C:\Ruta\A\Escanear' -DeepScan -AutoDisable" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Ejemplos:"
    Write-Host "   .\DLLVirusScan.ps1 -ScanPath 'C:\Windows\System32'" -ForegroundColor Cyan
    Write-Host "   .\DLLVirusScan.ps1 -ScanPath 'C:\Program Files' -DeepScan -AutoDisable" -ForegroundColor Cyan
    Write-Host "=============================================" -ForegroundColor Yellow
}

# Exportar funciones para uso en otros scripts
Export-ModuleMember -Function Start-DLLVirusScan, Test-SuspiciousDLL, Disable-SuspiciousDLL

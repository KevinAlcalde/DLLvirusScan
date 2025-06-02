# DLLVirusScan - Escáner y Desactivador de DLLs Maliciosos

Este script de PowerShell permite detectar y desactivar archivos DLL potencialmente maliciosos en sistemas Windows.

## Características

- Detección de archivos DLL sospechosos basada en múltiples criterios:
  - Tamaño del archivo
  - Ausencia de firma digital válida
  - Ubicación sospechosa
  - Fecha de creación reciente
  - Strings sospechosos en el contenido
- Desactivación segura de archivos maliciosos
- Creación automática de copias de seguridad en cuarentena
- Generación de reportes detallados
- Opciones de escaneo rápido o profundo
- Verificación de privilegios de administrador

## Requisitos

- Windows 7/8/10/11
- PowerShell 5.1 o superior
- Privilegios de administrador

## Instrucciones de Uso

1. Descargue el archivo `DLLVirusScan.ps1`
2. Abra PowerShell como administrador
3. Navegue hasta la ubicación del script
4. Ejecute el script con los parámetros deseados

### Ejemplos de Uso

#### Escaneo rápido (solo reporte):
```powershell
.\DLLVirusScan.ps1 -ScanPath 'C:\Ruta\A\Escanear'
```

#### Escaneo profundo (solo reporte):
```powershell
.\DLLVirusScan.ps1 -ScanPath 'C:\Ruta\A\Escanear' -DeepScan
```

#### Escaneo rápido con desactivación automática:
```powershell
.\DLLVirusScan.ps1 -ScanPath 'C:\Ruta\A\Escanear' -AutoDisable
```

#### Escaneo profundo con desactivación automática:
```powershell
.\DLLVirusScan.ps1 -ScanPath 'C:\Ruta\A\Escanear' -DeepScan -AutoDisable
```

## Seguridad

- El script crea copias de seguridad de todos los archivos desactivados
- Los archivos originales no son eliminados, solo renombrados
- Se mantiene un registro detallado de todas las acciones realizadas

## Advertencia

Este script debe ser utilizado con precaución. La desactivación de archivos DLL del sistema puede causar inestabilidad o fallos en el sistema operativo. Se recomienda utilizarlo primero en modo de solo reporte y revisar cuidadosamente los resultados antes de proceder con la desactivación automática.

## Limitaciones

- El script no puede detectar todos los tipos de malware
- Pueden producirse falsos positivos
- No reemplaza a un software antivirus completo

## Recuperación

Si un archivo legítimo es desactivado por error, puede restaurarlo manualmente:
1. Localice el archivo con extensión `.disabled`
2. Renómbrelo para quitar la extensión `.disabled`
3. Alternativamente, utilice la copia de seguridad en la carpeta de cuarentena

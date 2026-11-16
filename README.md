<p align="center">
  <img src="https://via.placeholder.com/800x200.png?text=PHP+Hunter+OSINT+Automation+Tool" alt="PHP Hunter Banner" width="100%">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue.svg?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Shodan-API-red.svg?style=for-the-badge&logo=shodan&logoColor=white" alt="Shodan">
  <img src="https://img.shields.io/badge/InternetDB-Enrichment-orange.svg?style=for-the-badge&logo=security&logoColor=white" alt="InternetDB">
</p>

---

# 🛡️ PHP Hunter (`phphunter.py`)

Herramienta de investigación OSINT automatizada para el mapeo y análisis de servidores PHP expuestos a nivel global utilizando la API oficial de Shodan e InternetDB. Este script ha sido desarrollado en el ámbito académico para auditar la exposición de versiones obsoletas (*End of Life*) y vulnerabilidades críticas recientes (como el caso `PHP2Shell`, CVE-2026-109618 y CVE-2026-109619).

---

## 📑 Tabla de Contenidos
- [Características principales](#-características-principales)
- [Requisitos previos](#-requisitos-previos)
- [Instalación y Configuración](#️-instalación-y-configuración)
- [Modo de Uso](#-modo-de-uso)
- [Estructura de los Archivos](#-estructura-de-los-archivos)
- [Aviso Legal](#️-aviso-legal)

---

## 🚀 Características principales
* **Consulta automatizada a Shodan:** Permite filtrar y extraer IPs expuestas mediante consultas avanzadas (`http.component:PHP`).
* **Enriquecimiento con InternetDB:** Obtiene de forma gratuita y sin coste de créditos los CPEs específicos de PHP, listados de CVEs y la presencia de vulnerabilidades recientes (`PHP2Shell`).
* **Clasificación de ramas tecnológicas:** Detecta automáticamente si la versión de PHP se encuentra con soporte activo o en estado *EOL* (End of Life).
* **Control de tasa de peticiones (*Rate Limiting*):** Incorpora pausas integradas (`time.sleep`) para cumplir estrictamente con los límites de la API y evitar bloqueos.
* **Exportación estructurada:** Vuelca todos los resultados analizados en un fichero `salida.csv` listo para su tratamiento estadístico.

---

## 📋 Requisitos previos
* **Python 3.8** o superior.
* Una cuenta en Shodan y su respectiva **API Key** (compatible con planes de desarrollador/académicos).

---

## ⚙️ Instalación y Configuración

1. **Clonar o descargar** este repositorio en tu máquina local.
2. **Crear y activar un entorno virtual** (`venv`) para aislar las dependencias:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```
3. **Instalar** las dependencias requeridas:
   ```bash
   pip install -r requirements.txt
   ```
4. **Configurar** la clave de la API:
Crea un archivo llamado .env en la raíz del proyecto y añade tu clave de Shodan de la siguiente manera:
   ```bash
   SHODAN_API_KEY=tu_api_key_de_shodan_aqui
   ```
  (Nota: El archivo .env está excluido en el .gitignore para evitar exponer credenciales públicamente).

---

## 🛠️ Modo de Uso

Una vez configurado el entorno y la clave de API, puedes ejecutar el script directamente desde la terminal:

```bash
python phphunter.py
```

Durante su ejecución, el script realizará los siguientes pasos de forma automatizada:
1. Validará el plan activo y los créditos disponibles en tu cuenta de Shodan.
2. Consultará los hosts expuestos filtrando por país (configurable en el código, por ejemplo, country:ES o country:FR).
3. Iterará sobre los resultados consultando la base de datos de InternetDB para cada IP.
4. Generará un informe por consola con el resumen estadístico y guardará los datos detallados en el archivo salida.csv.

---

## 📂 Estructura de los Archivos Generados
* phphunter.py: Script principal de automatización OSINT.
* requirements.txt: Librerías necesarias (shodan, requests, python-dotenv, etc.).
* salida.csv: Fichero de resultados con las columnas: ip, puerto, org, version, rama, cves_total y cve_reciente.

---

## ⚠️ Aviso Legal
Esta herramienta ha sido desarrollada con fines exclusivamente educativos y de investigación académica para la asignatura de ciberseguridad. El autor no se hace responsable del mal uso que se le pueda dar a la información obtenida.

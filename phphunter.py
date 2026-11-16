
"""phphunter.py — OSINT de servidores PHP expuestos
Fuentes: base de datos de Shodan (API) e InternetDB (pública y sin clave).
Uso didáctico: solo consulta bases de datos; nunca se conecta a los hosts."""

import csv
import os
import sys
import time
from collections import Counter
import requests
import shodan
from dotenv import load_dotenv

CONSULTA = "http.component:PHP country:FR"
CVE_RECENTES = ["CVE-2026-109618", "CVE-2026-109619"]
CSV_SALIDA = "salida.csv"

load_dotenv()
API_KEY = os.getenv("SHODAN_API_KEY")


def buscar_hosts(api, consulta):
    """Devuelve una lista de diccionarios, uno por host usando la API de Shodan."""
    resultados = api.search(consulta, page=1)
    print(f"[*] Total indexado en Shodan para '{consulta}': {resultados['total']}")
    print(f"[*] Hosts recuperados en esta página: {len(resultados['matches'])}\n")

    hosts = []
    for match in resultados["matches"]:
        # Intentar extraer la versión de PHP desde http.components si Shodan la tiene
        php_info = match.get("http", {}).get("components", {}).get("PHP", {})
        versiones_php = php_info.get("versions") or []
        version = versiones_php[0] if versiones_php else "desconocida"

        hosts.append({
            "ip": match["ip_str"],
            "puerto": match.get("port"),
            "org": match.get("org") or "desconocida",
            "version": str(version),
            "cves": []
        })
    return hosts

def buscar_hosts_desde_fichero(ruta="ips.txt"):
    """Variante Plan B (sin créditos): lee las IPs de un fichero de texto."""
    hosts = []
    try:
        with open(ruta, "r", encoding="utf-8") as f:
            for linea in f:
                ip = linea.strip()
                if ip:
                    hosts.append({
                        "ip": ip,
                        "puerto": None,
                        "org": "desconocida (Plan B)",
                        "version": "desconocida",
                        "cves": []
                    })
    except FileNotFoundError:
        print(f"[!] Error: No se encontró el fichero '{ruta}' para el Plan B.")
        sys.exit(1)
    return hosts


def clasificar_rama(version):
    """Devuelve '8.3'/'8.4'/'8.5' si la rama tiene soporte; 'EOL' si no; 'desconocida'."""
    if not version or version == "desconocida":
        return "desconocida"

    partes = version.split(".")
    if len(partes) < 2:
        return "desconocida"

    rama = f"{partes[0]}.{partes[1]}"
    ramas_soportadas = {"8.3", "8.4", "8.5"}

    if rama in ramas_soportadas:
        return rama
    return "EOL"


def consultar_internetdb(host_dict):
    """Consulta InternetDB para una IP, extrae CVEs y completa puerto/versión si faltan."""
    ip = host_dict["ip"]
    url = f"https://internetdb.shodan.io/{ip}"
    respuesta = requests.get(url, timeout=10)

    if respuesta.status_code == 404:
        return []

    respuesta.raise_for_status()
    datos = respuesta.json()

    if host_dict["puerto"] is None:
        host_dict["puerto"] = (datos.get("ports") or [None])[0]

    if host_dict["version"] == "desconocida":
        for cpe in datos.get("cpes") or []:
            partes = cpe.split(":")
            if "php" in partes:
                i = partes.index("php")
                if len(partes) > i + 2 and partes[i + 2]:
                    host_dict["version"] = partes[i + 2]
                    break

    vulns = datos.get("vulns") or []
    return [cve.strip().upper() for cve in vulns]


def main():
    if not API_KEY:
        print("[!] Error: No se encontró SHODAN_API_KEY en el entorno o en el archivo .env")
        sys.exit(1)

    try:
        api = shodan.Shodan(API_KEY)
        info = api.info()
        print(f"[*] Plan Shodan: {info.get('plan')} | Créditos de búsqueda: {info.get('query_credits')}\n")

        if info.get("query_credits", 0) > 0:
            hosts = buscar_hosts(api, CONSULTA)
        else:
            print("[!] Sin créditos de búsqueda disponibles. Ejecutando Plan B desde 'ips.txt'...\n")
            hosts = buscar_hosts_desde_fichero("ips.txt")

    except shodan.APIError as e:
        print(f"[!] Error de la API de Shodan: {e}")
        sys.exit(1)

    if not hosts:
        print("[!] No se obtuvieron hosts para analizar.")
        return

    cves_objetivo_upper = {cve.upper() for cve in CVE_RECENTES}
    hosts_afectados_recientes = []

    print("[*] Consultando InternetDB para enriquecer los hosts...")
    for idx, h in enumerate(hosts, start=1):
        try:
            cves = consultar_internetdb(h)
            h["cves"] = cves
            h["rama"] = clasificar_rama(h["version"])

            coincidencias = [c for c in cves if c in cves_objetivo_upper]
            h["cve_reciente"] = ", ".join(coincidencias) if coincidencias else "No"

            if coincidencias:
                hosts_afectados_recientes.append(h)

            print(f"  [{idx}/{len(hosts)}] {h['ip']} | PHP {h['version']} ({h['rama']}) | CVEs: {len(cves)} | PHP2Shell: {h['cve_reciente']}")

        except requests.RequestException as e:
            print(f"  [!] Error de red consultando InternetDB para {h['ip']}: {e}")
            h["cves"] = []
            h["rama"] = clasificar_rama(h["version"])
            h["cve_reciente"] = "Error"

        if idx < len(hosts):
            time.sleep(1)

    print("\n" + "=" * 60)
    print("RESUMEN DE RESULTADOS")
    print("=" * 60)

    conteo_versiones = Counter(h["version"] for h in hosts)
    print("\n[+] Top 5 versiones de PHP detectadas:")
    for ver, count in conteo_versiones.most_common(5):
        print(f"  - Versión {ver} ({clasificar_rama(ver)}): {count} hosts")

    conteo_ramas = Counter(h["rama"] for h in hosts)
    total_hosts = len(hosts)
    eol_count = conteo_ramas.get("EOL", 0)
    porcentaje_eol = (eol_count / total_hosts) * 100 if total_hosts else 0

    print(f"\n[+] Distribución por soporte:")
    for rama, count in conteo_ramas.items():
        print(f"  - {rama}: {count} ({count / total_hosts * 100:.1f}%)")
    print(f"  -> Porcentaje confirmado en ramas sin soporte (EOL): {porcentaje_eol:.1f}%")
    print(f"  -> Hosts con CVEs recientes (PHP2Shell): {len(hosts_afectados_recientes)}")

    columnas = ["ip", "puerto", "org", "version", "rama", "cves_total", "cve_reciente"]
    try:
        with open(CSV_SALIDA, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=columnas)
            writer.writeheader()
            for h in hosts:
                writer.writerow({
                    "ip": h["ip"],
                    "puerto": h["puerto"],
                    "org": h["org"],
                    "version": h["version"],
                    "rama": h["rama"],
                    "cves_total": len(h["cves"]),
                    "cve_reciente": h["cve_reciente"]
                })
        print(f"\n[*] Resultados exportados correctamente a '{CSV_SALIDA}'.")
    except OSError as e:
        print(f"[!] Error al escribir el archivo CSV: {e}")


if __name__ == "__main__":
    main()

# 🛡️ Guía Definitiva para Principiantes: Análisis de Correos Electrónicos Maliciosos 📧

## ✨ Introducción

> El correo electrónico: esencial para comunicarnos, pero un campo minado de amenazas digitales. Phishing, malware, robo de datos... Aprender a **identificar y analizar** emails sospechosos no es opcional, ¡es **fundamental** para tu seguridad digital!

Esta guía es tu punto de partida. Te llevaremos paso a paso por los conceptos básicos para convertirte en un detector de correos maliciosos.

---

## 🚩 Parte 1: Detección - ¿Cómo Identificar un Correo Sospechoso? (Red Flags)

Antes de analizar, ¡hay que sospechar! Estas son las **señales de alerta (Red Flags)** que deben encender tus alarmas:

1.  **👤 Remitente Desconocido o Extraño:**
    * Dirección no reconocida.
    * Nombre legítimo (`Soporte Técnico`) pero con email genérico (`soporte.urgente.1984@hotmail.com`) o dominio incorrecto.
    * **Typosquatting:** Errores sutiles en el dominio (ej: `info@microsofft.com`, `banco@paypa1.com`).

2.  **🚨 Asunto y Contenido Urgentes o Amenazantes:**
    * **Presión:** "¡Actúa AHORA o tu cuenta será eliminada!"
    * **Amenazas:** "Detectamos actividad ilegal, haz clic aquí para evitar consecuencias."
    * **Ofertas Irresistibles:** Premios, dinero fácil, ¡demasiado bueno para ser verdad!

3.  **✉️ Saludos Genéricos:**
    * "Estimado cliente", "Hola usuario". Las empresas serias suelen usar tu nombre.

4.  **✍️ Errores Gramaticales y de Ortografía:**
    * Redacción pobre, frases extrañas, mala traducción. Indica falta de profesionalismo o automatización maliciosa.

5.  **🔒 Solicitudes de Información Sensible:**
    * **¡NUNCA!** Nadie legítimo te pedirá contraseñas, números de tarjeta, DNI, códigos 2FA por correo.

6.  **🔗 Enlaces (URLs) Sospechosos:**
    * **Hover (sin clic):** ¿La URL que aparece abajo es distinta al texto del enlace? ¿Apunta a un dominio raro?
    * **Acortadores:** `bit.ly`, `tinyurl` pueden ocultar destinos maliciosos. ¡Doble precaución!

7.  **📎 Archivos Adjuntos Inesperados o Peligrosos:**
    * ¿No esperabas ese archivo? ¿Es un tipo potencialmente peligroso? (`.exe`, `.js`, `.vbs`, `.bat`, `.scr`, `.zip` sospechoso, `.docm`, `.xlsm` que piden macros).

8.  **🤔 Inconsistencias:**
    * Firma diferente a correos anteriores.
    * Tono o estilo inusual para ese remitente.

---

## 🕵️‍♀️ Parte 2: Análisis Básico - ¿Qué Hacer si Sospechas?

> **⚠️ ¡ALTO AHÍ! LA REGLA DE ORO: NO INTERACTÚES DIRECTAMENTE ⚠️**
>
> * **NO** hagas clic en NADA.
> * **NO** descargues NADA.
> * **NO** respondas.
> * **NO** reenvíes (excepto a equipos de seguridad designados).

**Pasos iniciales seguros:**

1.  **Aislar (Mentalmente):** Trata ese correo como una "bomba" sin explotar. 💣
2.  **Observar:** Repasa las *Red Flags* de la Parte 1.
3.  **Investigar Cabeceras:** ¡La caja negra del email! 📦

---

## ራስ Parte 3: Análisis de Cabeceras (Headers)

Las cabeceras son los metadatos técnicos del viaje del correo. ¡Oro puro para el análisis!

**❓ ¿Cómo ver las cabeceras?**

* **Gmail:** Abre el email -> Menú ⋮ (tres puntos verticales) junto a Responder -> `Mostrar original`.
* **Outlook (App Escritorio):** Doble clic para abrir en ventana nueva -> `Archivo` -> `Propiedades` -> Mira en `Encabezados de Internet`.
* **Outlook (Web - OWA):** Abre el email -> Menú ··· (tres puntos horizontales) -> `Ver` -> `Ver detalles del mensaje`.

**Campos Clave a Revisar:**

* `From:`: Quién *dice* ser. **Puede ser falso.**
* `Reply-To:`: A quién responderás realmente. Si difiere del `From:` sin razón, ¡sospechoso!
* `Received:`: La ruta del email (leer de abajo a arriba). Busca saltos extraños, IPs/servidores no esperados. El `Received:` más bajo suele ser el origen.
* `Return-Path:` (o `Envelope-From`): Dónde van los rebotes. Suele ser una dirección controlada por el atacante.
* `Authentication-Results:`: **¡CRUCIAL!** ¿Pasó los chequeos de autenticidad?
    * **SPF (Sender Policy Framework):** ¿El servidor que envió (`IP`) estaba autorizado por el dominio (`From:`)?
        * `spf=pass`: 👍 Bueno.
        * `spf=fail`: 👎 Malo. Suplantación probable.
        * `spf=softfail`/`neutral`/`none`: 🤔 Sospechoso/Inconcluso. Requiere más análisis.
    * **DKIM (DomainKeys Identified Mail):** ¿La firma digital del correo es válida y del dominio correcto?
        * `dkim=pass`: 👍 Bueno.
        * `dkim=fail`/`none`: 👎 Malo o sospechoso (si el dominio suele firmar).
    * **DMARC (Domain-based Message Authentication, Reporting & Conformance):** Política del dominio si SPF/DKIM fallan.
        * `dmarc=pass`: 👍 Bueno (SPF o DKIM pasaron y alinearon).
        * `dmarc=fail`: 👎 Malo (Indica que el dominio quiere que se rechace/cuarentene este tipo de fallo).
* `X-Originating-IP:` o IPs en `Received:`: IPs de origen o intermedias. ¡Búscalas en bases de datos de reputación!

---

## 📄🔗📎 Parte 4: Análisis del Contenido y Enlaces/Adjuntos (Sin Interactuar)

1.  **Texto del Mensaje:** Revisa *Red Flags* (urgencia, errores...). ¿Suena como la persona/entidad real? ¿La oferta es lógica?

2.  **Enlaces (URLs):**
    * 🖱️ **Hover:** ¡Siempre! Mira la URL real en la barra de estado.
    * 📋 **Copiar enlace (CON CUIDADO):** Clic derecho -> "Copiar dirección de enlace". **NUNCA ABRIR.** Pégalo en un bloc de notas o directo a una herramienta de análisis (Parte 6).
    * 🧐 **Analiza la URL copiada:**
        * ¿Dominio esperado? (`banco.com` vs `banco-seguro.xyz`)
        * ¿HTTP en lugar de HTTPS? 🚩
        * ¿Caracteres raros (`%20`, `%3D`)? ¿Excesivos subdominios? (`login.secure.app.banco.com.hacker.net`)

3.  **Archivos Adjuntos:**
    * **Nombre/Tipo:** Genérico (`factura.pdf`, `scan001.zip`) + Tipo peligroso (`.exe`, `.js`, `.docm`...). ¿Extensión oculta (`factura.pdf.exe`)?
    * **Análisis Externo (Sandbox):**
        > **☢️ ¡NUNCA ABRAS ADJUNTOS SOSPECHOSOS EN TU MÁQUINA! ☢️**
        > Descárgalo (con máxima precaución, idealmente en entorno aislado) y súbelo a un sandbox online (Parte 6).

---

## 🎯 Parte 5: Indicadores de Compromiso (IOCs)

Los IOCs son las "huellas dactilares" del ataque. ¡Colecciónalos!

| Tipo de IOC                       | Dónde Encontrarlo (Ejemplos)                               | Utilidad                                       |
| :-------------------------------- | :--------------------------------------------------------- | :--------------------------------------------- |
| **Direcciones IP** 🌐             | Cabeceras (`Received:`, `X-Originating-IP`), URLs          | Reputación, Bloqueo (Firewall), Correlación    |
| **Dominios y URLs** 🔗            | Cabeceras (`From:`, `Reply-To:`), Cuerpo del mensaje, Links | Reputación, Bloqueo (DNS/Proxy), Correlación   |
| **Direcciones de Correo** 📧      | Cabeceras (`From:`, `Reply-To:`, `Return-Path:`)           | Listas negras, Reglas de filtrado, Búsquedas   |
| **Hashes de Archivos** (MD5/SHA) #️⃣ | Resultado de análisis de adjuntos (VirusTotal, etc.)   | Detección (Antivirus), Búsqueda (Threat Intel) |
| **Asuntos del Correo** ✉️         | Cabecera (`Subject:`)                                      | Identificar campañas, Reglas de filtrado       |

Usa estos IOCs para buscar en plataformas de Threat Intelligence y para configurar defensas.

---

## 🛠️ Parte 6: Herramientas Útiles para el Análisis

¡No estás solo! Estas herramientas online (la mayoría gratuitas) son tus mejores aliadas:

| Categoría                      | Herramienta(s) Recomendada(s)                                                                                                                                                           | Propósito Principal                                            |
| :----------------------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :------------------------------------------------------------- |
| **Analizadores de Cabeceras** | [MXToolbox](https://mxtoolbox.com/EmailHeaders.aspx), [Google Messageheader](https://toolbox.googleapps.com/apps/messageheader/)                                                          | Hacer legibles las cabeceras, resaltar IPs y resultados Auth. |
| **Escáneres URL/Archivo** | [**VirusTotal**](https://www.virustotal.com/) (URLs, Archivos, IPs, Dominios, Hashes), [URLScan.io](https://urlscan.io/) (Scan detallado de URL)                                           | Chequear seguridad SIN visitar/ejecutar. ¡Esencial!            |
| **Sandboxes (Entorno Seguro)** | [Any.Run](https://any.run/) (Interactivo), [Hybrid Analysis](https://www.hybrid-analysis.com/), [VirusTotal Sandbox](https://www.virustotal.com/gui/file/upload) (Dentro de VT)            | Ejecutar/abrir el contenido en un entorno aislado y observar. |
| **Reputación / Threat Intel** | [AbuseIPDB](https://www.abuseipdb.com/) (IPs reportadas), [Talos Intelligence](https://talosintelligence.com/reputation_center) (IP/Dominio), [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/) | Buscar IOCs y ver si son conocidos por maliciosos.           |

**Workflow Simplificado con Herramientas:**

1.  **🔍 Cabeceras:** Pega en Analizador -> Revisa `From`, `Reply-To`, `Received` (IPs), `Auth-Results`.
2.  **📊 IOCs:** Extrae IPs/Dominios/Emails -> Busca en VirusTotal, AbuseIPDB, Talos.
3.  **🔗 Enlaces:** Copia URL (sin visitar) -> Pega en VirusTotal, URLScan.io.
4.  **📎 Adjuntos:** Descarga con cuidado (¡idealmente aislado!) -> Sube a VirusTotal / Any.Run / Hybrid Analysis -> Busca el Hash resultante.

---

## ✅👉 Parte 7: Pasos Siguientes y Buenas Prácticas

* **Si confirmas Malicia:**
    * **📢 Reporta:** Usa "Marcar como Phishing/Spam". **¡Reporta a tu equipo IT/Seguridad si aplica!** Proporciona el `.eml`/`.msg` original si puedes.
    * **🗑️ Elimina:** ¡Fuera de tu vista! (Bandeja de entrada Y Papelera).
* **🆘 Si Interactuaste por Error (Clic/Apertura):**
    * **🔌 ¡DESCONECTA DE LA RED INMEDIATAMENTE! (WiFi/Cable)**
    * **📞 Contacta a IT/Seguridad URGENTEMENTE.**
    * **🔑 Cambia contraseñas** si las introdujiste o sospechas compromiso.
* **🛡️ Buenas Prácticas Generales (Prevención):**
    * ✅ Mantén TODO actualizado (SO, Navegador, Antivirus).
    * ✅ Usa contraseñas FUERTES y ÚNICAS (¡gestor de contraseñas!).
    * ✅ Activa **Autenticación Multi-Factor (MFA)** SIEMPRE.
    * ✅ Realiza Copias de Seguridad (Backup) regularmente.
    * ✅ **Desconfía por Defecto:** Piensa antes de hacer clic. Ante la duda, no actúes.

---

## ✨ Conclusión

> El análisis de correos es un arte que mezcla **escepticismo**, **observación** y el uso inteligente de **herramientas**. No necesitas ser un experto para empezar a protegerte mejor.

La clave: **Precaución ➕ Observación ➕ No interacción directa**. ¡Con cada correo sospechoso que analices (de forma segura!), te volverás más hábil! 💪 ¡Mantente alerta!

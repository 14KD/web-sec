# Código de Ética y Declaración de Responsabilidad (ETHICS.md)

## 1. Declaración de Misión
**WebSec Auditor** es un proyecto de código abierto desarrollado para ayudar a estudiantes, desarrolladores y profesionales de ciberseguridad a evaluar la postura defensiva de sus propias aplicaciones web de manera ética, autorizada y no destructiva.

## 2. Reglas Éticas de Ejecución Obligatorias
1. **Autorización Escrita Previa:** El usuario de este software se compromete a ejecutar auditorías únicamente sobre dominios de su propiedad o sobre los cuales posea una autorización contractual explícita y por escrito.
2. **Naturaleza No Destructiva:**
   - La herramienta envía sondas de detección (ej. marcadores alfanuméricos inofensivos para XSS o comillas simples para detectar errores de sintaxis).
   - **NUNCA** se ejecuta explotación real de vulnerabilidades (no se extrae información de bases de datos, no se ejecutan comandos, no se modifican registros, no se toman cuentas).
3. **Prohibiciones Absolutas:**
   - Queda estrictamente excluido el uso de fuerza bruta sobre credenciales o tokens de sesión.
   - Quedan excluidos los ataques de Denegación de Servicio (DoS).
   - Queda prohibido el bypass de controles de autenticación.
4. **Respeto a los Recursos:**
   - La velocidad predeterminada está limitada a 2 peticiones/segundo con User-Agent claramente identificado (`WebSecAuditor/1.0`).

## 3. Descargo de Responsabilidad (Disclaimer)
Los desarrolladores y contribuidores de WebSec Auditor no se hacen responsables del uso ilícito, indebido, malicioso o no autorizado que terceros puedan dar a este software. El usuario asume toda la responsabilidad legal derivada de sus acciones.

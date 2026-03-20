# EvoNHI SaaS — Documento Maestro del Proyecto

## 1. Qué es EvoNHI

EvoNHI es una plataforma SaaS de ciberseguridad enfocada en **identidades no humanas** dentro de entornos cloud-native, especialmente Kubernetes. Su propósito es ayudar a las organizaciones a responder una pregunta que hoy sigue siendo difícil de contestar con claridad:

**¿Qué cambios de seguridad conviene hacer primero para reducir caminos de ataque hacia activos críticos, sin gastar de más y sin romper producción?**

La mayoría de herramientas actuales muestran exposición, permisos excesivos o posibles rutas de ataque. EvoNHI busca ir un paso más allá: convertir esa visibilidad en **decisiones concretas de remediación**.

No quiere ser solo un escáner. Quiere ser un sistema que ayude a decidir **cómo defender mejor** un entorno real.

---

## 2. El problema que resuelve

En entornos modernos hay cada vez más:

- service accounts
- tokens
- secrets
- permisos RBAC
- relaciones entre workloads
- automatizaciones con privilegios amplios

Todo eso forma una red de accesos automáticos. El problema es que, cuando esa red crece, ya no basta con saber que "hay permisos de más". Lo difícil es entender:

- qué permisos abren rutas de ataque reales
- cuáles conectan con activos críticos
- qué accesos sirven como pivote para avanzar
- y qué combinación de cambios reduce más riesgo con menor costo

En la práctica, muchos equipos enfrentan cuatro dolores al mismo tiempo:

### 2.1 Demasiado hallazgo, poca decisión
Las herramientas producen listas largas de problemas, pero no siempre priorizan bien qué conviene corregir primero.

### 2.2 Falta de visión conectada
Un permiso aislado puede parecer menor, pero combinado con un token montado, un secret y una binding incorrecta puede formar una ruta crítica.

### 2.3 Presupuesto y tiempo limitados
No se puede arreglar todo al mismo tiempo. La remediación siempre compite contra otras prioridades.

### 2.4 Endurecer sin romper
Una recomendación técnicamente "segura" puede ser operativamente inviable si rompe workloads, pipelines o flujos de negocio.

EvoNHI nace para tratar estos cuatro problemas como uno solo.

---

## 3. Tesis central del producto

La tesis central del proyecto es esta:

**La seguridad de identidades no humanas no debe resolverse solo con detección, sino con optimización de remediaciones bajo restricciones reales.**

Eso significa que EvoNHI no se enfoca primero en decir:

- “hay un problema aquí”
- “hay un sobreprivilegio allá”
- “hay un secret expuesto”

Sino en responder:

- “si solo puedes hacer tres cambios esta semana, estos son los que más reducen riesgo”
- “esta combinación corta más caminos de ataque que otras opciones”
- “este plan cabe en el presupuesto y no debería afectar demasiado la operación”

Ese cambio de enfoque es el corazón del proyecto.

---

## 4. Qué vende EvoNHI como SaaS

EvoNHI no vende únicamente análisis. Vende una capacidad continua.

### Promesa del producto

**Convertir exposición técnica en decisiones de defensa accionables y priorizadas.**

### Resultado que entrega

- inventario útil de identidades no humanas relevantes
- visualización lógica de cómo esas identidades participan en caminos de ataque
- definición explícita de crown jewels
- análisis reproducibles en el tiempo
- planes de remediación priorizados
- balance entre seguridad, costo e impacto operativo

### Valor para el cliente

- menos tiempo decidiendo por intuición
- menos endurecimiento a ciegas
- menos remediaciones con poco valor
- mejor uso del presupuesto de seguridad
- más claridad para justificar acciones ante líderes técnicos o de negocio

---

## 5. En qué se enfoca el proyecto

EvoNHI se enfoca en el cruce entre estas piezas:

- identidades no humanas
- permisos y bindings
- tokens y secrets
- relaciones de confianza
- workloads expuestos
- activos críticos
- caminos de ataque
- remediación priorizada

### Fuera de foco en esta etapa
Para mantener una dirección clara, el proyecto no pretende resolver desde el inicio:

- detección general de malware
- fraude transaccional
- SIEM/SOC completo
- respuesta autónoma en tiempo real
- federated learning
- multi-cloud total desde el primer día
- monitoreo de runtime profundo

No porque sean malos temas, sino porque diluyen el núcleo del producto.

---

## 6. Qué significa “identidad no humana” para EvoNHI

En este proyecto, una identidad no humana es cualquier identidad o credencial usada por sistemas, servicios, automatizaciones o workloads en lugar de personas.

Ejemplos:

- service accounts
- tokens de acceso
- secrets con credenciales
- identidades de workloads
- cuentas técnicas usadas por pods o servicios

Estas identidades importan porque son parte del movimiento real del sistema. Un atacante no necesita una cuenta humana si puede comprometer un workload, obtener su token y pivotear con sus permisos.

---

## 7. Qué significa “crown jewel”

Un crown jewel es un activo que merece protección prioritaria porque su exposición tendría alto impacto.

Ejemplos:

- secretos de base de datos
- llaves de acceso sensibles
- servicios críticos
- recursos con datos delicados
- workloads con privilegios altos

EvoNHI no quiere optimizar para “bajar hallazgos en general”. Quiere optimizar para **reducir rutas hacia lo verdaderamente importante**.

---

## 8. Qué significa “attack path”

Un attack path es una secuencia de pasos que un atacante podría seguir para avanzar desde un punto de entrada hasta un activo crítico.

En EvoNHI, un camino de ataque puede incluir cosas como:

- un workload público comprometido
- uso del token de su service account
- acceso a un permiso relevante
- lectura de un secret
- pivot a otra identidad
- llegada a un crown jewel

La idea no es analizar permisos como piezas sueltas, sino entender cómo se conectan en una ruta útil para un atacante.

---

## 9. Qué hace EvoNHI en términos simples

EvoNHI hace cinco cosas principales:

### 9.1 Recibe un entorno
Por ahora, usando manifests de Kubernetes. Más adelante, esto puede evolucionar a conectores reales.

### 9.2 Entiende su estructura de acceso
Lee service accounts, roles, bindings, secrets y workloads para construir una representación lógica.

### 9.3 Encuentra caminos de ataque
Analiza cómo podría moverse un atacante desde workloads expuestos hacia activos críticos.

### 9.4 Genera cambios posibles
Propone acciones defensivas como quitar permisos, limitar accesos o reducir exposición de secrets.

### 9.5 Busca la mejor combinación de cambios
Usa optimización multiobjetivo para producir planes de remediación con mejor equilibrio entre:

- reducción de caminos de ataque
- costo
- impacto operativo

Ese último punto es lo que le da forma de producto diferenciador.

---

## 10. Por qué el enfoque es SaaS y no solo herramienta local

Porque el problema real no es ejecutar un análisis una vez. El problema real es operar esa capacidad como servicio continuo.

### Un SaaS permite:

- tener múltiples clientes
- guardar análisis históricos
- comparar ejecuciones
- manejar varios entornos por cliente
- generar salidas reutilizables
- crecer hacia paneles, alertas, reportes y flujos de trabajo

### Objetos nativos del producto
EvoNHI está pensado alrededor de estos objetos de negocio:

- **Tenant:** el cliente
- **Workspace:** el equipo o unidad del cliente
- **Environment:** el clúster o entorno analizado
- **Crown Jewel:** el activo crítico declarado
- **Analysis Run:** una corrida de análisis fechada
- **Remediation Plan:** la salida accionable del sistema

Eso es importante porque la plataforma debe comportarse como producto, no como notebook técnico.

---

## 11. Principios de diseño del proyecto

### 11.1 Menos alertas, más decisiones
EvoNHI no persigue volumen de findings. Persigue calidad de decisión.

### 11.2 Seguridad con contexto
No basta con detectar exposición. Hay que entender impacto y conectividad.

### 11.3 Optimización bajo límites reales
La plataforma asume restricciones de tiempo, presupuesto y continuidad operativa.

### 11.4 Producto antes que demo aislada
El diseño debe poder crecer hacia autenticación, facturación, jobs, reportes y gobierno.

### 11.5 Primero claridad, después complejidad
La arquitectura inicial debe ser simple de entender y sólida de extender.

---

## 12. Arquitectura conceptual del SaaS

La forma correcta de ver EvoNHI es como una **control plane de seguridad**.

### Capa 1 — API del producto
Expone las operaciones del SaaS:

- crear tenants
- crear workspaces
- registrar entornos
- registrar crown jewels
- lanzar análisis
- consultar planes de remediación
- ver resumen de riesgo por cliente

### Capa 2 — Servicios de aplicación
Orquesta la lógica del producto:

- onboarding
- persistencia
- preparación del escenario
- ejecución del motor
- almacenamiento de resultados
- armado de salidas consumibles por el cliente

### Capa 3 — Motor de análisis
Contiene el valor técnico principal:

- parseo de manifests
- construcción de attack graph
- búsqueda de caminos de ataque
- catálogo de remediaciones
- optimización multiobjetivo

### Capa 4 — Persistencia
Guarda entidades del SaaS y resultados históricos:

- tenants
- workspaces
- environments
- crown jewels
- analysis runs
- remediation plans

---

## 13. Arquitectura del MVP actual

El MVP entregado se enfoca totalmente a la forma SaaS.

### Incluye

- backend con FastAPI
- base SQLite
- modelo multi-tenant
- flujos de onboarding
- análisis persistido como objeto del producto
- planes de remediación guardados en la plataforma
- escenario demo reproducible

### No incluye todavía

- autenticación de usuarios
- billing
- colas asíncronas
- conectores live a clusters
- frontend web
- auditoría completa
- observabilidad de producción

Esto no es una carencia accidental. Es una decisión deliberada de alcance.

---

## 14. Flujo del producto

### Paso 1: Alta del cliente
Se crea un tenant.

### Paso 2: Organización del cliente
Se crean workspaces para separar equipos o ambientes.

### Paso 3: Registro del entorno
El cliente registra un environment y apunta al origen del análisis.

### Paso 4: Declaración de crown jewels
Se define qué quiere proteger primero.

### Paso 5: Corrida de análisis
El SaaS ejecuta el motor y guarda un snapshot de riesgo.

### Paso 6: Generación de planes
Se almacenan las mejores combinaciones de remediación.

### Paso 7: Revisión
El cliente consume resultados desde la plataforma, no desde scripts sueltos.

---

## 15. Núcleo técnico del sistema

### 15.1 Ingesta
La plataforma necesita una representación del entorno. En el MVP esto ocurre mediante manifests locales porque es la forma más controlada y reproducible.

### 15.2 Modelo del entorno
Se construye un modelo de:

- service accounts
- roles
- role bindings
- secrets
- workloads
- network policies básicas

### 15.3 Grafo de ataque
Ese modelo se transforma en un grafo dirigido donde los nodos representan recursos y permisos, y las aristas representan posibles relaciones de aprovechamiento.

### 15.4 Hallazgo de paths
Desde workloads expuestos se exploran caminos hacia crown jewels.

### 15.5 Catálogo de acciones
A partir del grafo se generan remediaciones posibles.

### 15.6 Optimización
Se ejecuta una búsqueda multiobjetivo para seleccionar planes con buen equilibrio entre seguridad, costo e impacto.

### 15.7 Persistencia del resultado
Cada plan se guarda como un resultado del producto.

---

## 16. Por qué la optimización es el corazón del producto

Sin la optimización, EvoNHI sería otra herramienta de exposición.

La optimización es la parte que lo vuelve diferente porque transforma la pregunta desde:

- “¿qué está mal?”

hacia:

- “¿qué conviene hacer primero?”

Eso es importante por tres razones:

### 16.1 Hay muchas posibles remediaciones
No basta con encontrar una. Hay que elegir una combinación inteligente.

### 16.2 Los objetivos compiten entre sí
Más seguridad puede significar más costo o más riesgo operativo.

### 16.3 El cliente necesita trade-offs, no absolutos
El mejor plan no siempre es el más agresivo. A veces es el más balanceado.

---

## 17. Objetivos que optimiza EvoNHI

En su forma actual, EvoNHI optimiza principalmente:

- reducción de attack paths a crown jewels
- costo estimado de la remediación
- impacto operativo estimado

En versiones más maduras puede incluir:

- cobertura por tipo de activo
- tiempo de implementación
- confianza del resultado
- blast radius residual
- deuda de permisos remanente

---

## 18. Qué representa “costo” en el sistema

El costo no es solo dinero. Es una abstracción de esfuerzo de cambio.

Puede representar cosas como:

- complejidad del ajuste
- coordinación entre equipos
- esfuerzo de despliegue
- tiempo de prueba
- fricción operativa

Esto es clave porque la seguridad real siempre compite con capacidad de ejecución.

---

## 19. Qué representa “impacto operativo”

Es una estimación del riesgo de que una remediación afecte el funcionamiento esperado del sistema.

No significa que el sistema sepa con certeza qué va a romperse. Significa que intenta capturar una idea central:

**no todo cambio seguro es un cambio seguro para producción.**

Ese criterio hace que EvoNHI sea más útil que una lógica de hardening ciego.

---

## 20. Qué hace valioso al enfoque para clientes reales

### 20.1 Traducir complejidad en decisión accionable
Muchos clientes no necesitan más teoría. Necesitan saber qué hacer primero.

### 20.2 Justificar prioridades
Un plan con cobertura, costo e impacto estimados es más fácil de defender frente a líderes y operaciones.

### 20.3 Repetibilidad
El cliente puede volver a correr análisis y observar si la superficie de ataque mejora o empeora.

### 20.4 Escalabilidad comercial
Una vez que el motor existe, el SaaS puede crecer en clientes y entornos sin rehacer el producto desde cero.

---

## 21. Perfil del cliente ideal

En una fase temprana, EvoNHI encaja bien con organizaciones que:

- operan Kubernetes o entornos cloud-native
- ya tienen cierta complejidad de permisos e identidades
- no quieren depender solo de revisión manual
- necesitan priorización más inteligente
- quieren justificar acciones de remediación con criterios claros

Más adelante, ese enfoque puede adaptarse a segmentos sectoriales como fintechs o microfinancieras, pero la base tecnológica debe nacer general y fuerte.

---

## 22. Por qué no conviene arrancar directamente con microfinanzas como núcleo

Aunque el futuro comercial puede apuntar a ese sector, para la etapa actual del proyecto conviene partir desde la ruta tecnológica por varias razones:

- la validación técnica es más clara
- el benchmarking es más defendible
- el alcance es más manejable
- se evita mezclar demasiadas variables de negocio desde el día uno

La ruta correcta es:

1. demostrar valor técnico sólido
2. convertir eso en producto reusable
3. luego sectorizar el posicionamiento comercial

---

## 23. Qué incluye el MVP entregado y por qué

El MVP que acompaña este documento es deliberadamente una base de plataforma, no un simple script.

### Incluye

- API HTTP
- persistencia relacional
- entidades multi-tenant
- onboarding de entornos
- análisis con motor interno
- almacenamiento de resultados
- escenario demo
- pruebas básicas
- documentación técnica

### Por qué está así
Porque la forma del producto importa tanto como el algoritmo. El MVP ya te obliga a pensar como SaaS:

- quién es el cliente
- qué entidad pertenece a quién
- qué queda guardado
- cómo se vuelve a consultar
- cómo se expone el resultado

---

## 24. Qué no se debe perder al evolucionar el proyecto

Hay varias tentaciones típicas que podrían debilitar la idea si se toman demasiado pronto.

### 24.1 Convertirlo en otro scanner
Eso haría perder el diferencial.

### 24.2 Meter demasiada detección con ML desde el inicio
Eso diluye el corazón de optimización.

### 24.3 Tratar de cubrir toda la nube desde la v1
Eso rompe el foco.

### 24.4 Saltar a un frontend complejo antes de fijar el backend
Primero debe quedar sólida la lógica del producto.

### 24.5 Prometer autonomía total
La propuesta gana más siendo honesta: asistencia estratégica de remediación, no magia negra.

---

## 25. Riesgos del proyecto

### Riesgo 1: modelado insuficiente del impacto operativo
Si se modela mal, las recomendaciones pueden ser poco creíbles.

### Riesgo 2: paths simplificados
Un MVP usa abstracciones. El reto será ir refinando sin perder claridad.

### Riesgo 3: exceso de alcance
Agregar runtime, multi-cloud, identidades SaaS externas y política compleja demasiado pronto podría frenar el proyecto.

### Riesgo 4: convertirlo en producto sin hardening de plataforma
Como SaaS, la seguridad del propio SaaS será un tema crítico más adelante.

---

## 26. Roadmap razonable del producto

### Fase 1 — SaaS base
- modelo multi-tenant
- API de onboarding
- análisis desde manifests
- top remediation plans

### Fase 2 — Producto usable
- autenticación
- background jobs
- panel web
- comparación histórica de runs
- exportación de reportes

### Fase 3 — Integración real
- conectores a clusters
- sincronización periódica
- detección de drift
- reanálisis automáticos

### Fase 4 — Inteligencia comercial
- segmentación por tipo de cliente
- perfiles de riesgo
- sugerencias por industry pack
- módulos específicos para sectores como fintech o MFI

---

## 27. Qué piezas futuras tienen más sentido

Cuando el producto madure, estas extensiones sí tienen sentido:

- PostgreSQL en lugar de SQLite
- workers asíncronos
- autenticación por tenant y usuarios internos
- auditoría de acciones
- comparativas de runs
- políticas más ricas
- conectores reales a Kubernetes
- integración con motores policy-as-code
- dashboard y reportes ejecutivos

Pero ninguna de esas extensiones debe desplazar el núcleo: **optimización de remediación para caminos de ataque en identidades no humanas**.

---

## 28. Cómo debe explicarse EvoNHI de forma simple

### Versión simple
EvoNHI es una plataforma que ayuda a decidir qué cambios de seguridad conviene hacer primero en un entorno cloud para cerrar los caminos de ataque más peligrosos sin afectar demasiado la operación.

### Versión producto
EvoNHI toma entornos cloud-native, entiende cómo los accesos automáticos pueden ser usados por un atacante y genera planes de defensa priorizados, medibles y más inteligentes que una revisión manual.

### Versión ejecutiva
No solo muestra exposición. Ayuda a decidir la mejor secuencia de remediación bajo presupuesto y con foco en activos críticos.

---

## 29. Frases que representan bien el alma del proyecto

- Menos alertas, más decisiones útiles.
- Menos endurecimiento ciego, más defensa estratégica.
- Menos exposición pasiva, más remediación inteligente.
- No queremos solo encontrar riesgos; queremos ayudar a decidir cómo reducirlos mejor.

---

## 30. Conclusión

EvoNHI tiene sentido como SaaS porque el valor que propone no es puntual ni aislado. Es una capacidad repetible de análisis, priorización y remediación.

Su fuerza no está en ser otro detector de hallazgos. Su fuerza está en convertir entornos complejos de identidades no humanas en una secuencia defendible de decisiones de seguridad.

Eso le da tres ventajas fuertes:

1. una propuesta técnica clara
2. una forma de producto escalable
3. una narrativa comercial comprensible

La esencia del proyecto puede resumirse así:

**EvoNHI es una plataforma SaaS que analiza accesos automáticos, permisos y secretos en entornos cloud-native para encontrar y priorizar la mejor forma de cerrar caminos de ataque hacia activos críticos con el menor costo posible y sin romper el sistema.**

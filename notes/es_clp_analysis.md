# Полный разбор ЭС из `network_security_assessment.clp`

## 1. Назначение системы

Экспертная система анализирует сетевые события и выдает решения по безопасности:
- обнаруживает типовые угрозы (DDoS, brute-force, port scan, DNS tunneling, SQL injection);
- оценивает риск;
- формирует вердикты по сервисам и инфраструктуре (`block`, `monitor`, `escalate`, `isolate`).

Центральный файл: `./network_security_assessment.clp`.

Теоретическая опора по CLIPS: `[Частиков и др., 2003, гл. 4-6]`.

## 2. Архитектура модели (на одном листе)

Поток данных в текущей реализации:

`traffic-event` -> `raw-observation` -> `threat-indicator` -> `attack-assessment` -> `candidate-action` -> `security-verdict`

Управление порядком выполнения сделано через служебный факт:
- `analysis-stage (n X)`.

Каждое правило обычно:
1. ищет текущий stage;
2. `retract` старого stage;
3. `assert` новых фактов + следующего stage.

Это делает систему детерминированной и похожей на конвейер шагов.

## 3. Структуры данных (`deftemplate`)

Ниже для каждой структуры даны:
- исходный фрагмент из `.clp`;
- таблица по всем слотам.

### 3.1 `network-node` (инфраструктурный узел)

```clips
(deftemplate network-node
  (slot id)
  (slot role)
  (slot os)
  (slot criticality)
  (slot zone))
```

| Слот | Комментарий |
|---|---|
| `id` | Уникальный идентификатор узла (`web1`, `db1`, `dns1`). |
| `role` | Функциональная роль узла (`web`, `db`, `dns`). |
| `os` | Тип ОС узла (в примере `linux`). |
| `criticality` | Критичность актива (`high`/`medium`), влияет на строгость решений. |
| `zone` | Сетевая зона узла (`dmz`, `internal`). |

### 3.2 `traffic-event` (входное событие трафика)

```clips
(deftemplate traffic-event
  (slot src)
  (slot dst)
  (slot protocol)
  (slot port)
  (slot rate)
  (slot failed-logins)
  (slot payload)
  (slot time-window))
```

| Слот | Комментарий |
|---|---|
| `src` | IP/идентификатор источника события. |
| `dst` | Целевой узел события. |
| `protocol` | Протокол (`tcp`, `udp`). |
| `port` | Целевой порт. |
| `rate` | Интенсивность потока (`low`, `medium`, `high`). |
| `failed-logins` | Число неуспешных логинов (важно для brute-force). |
| `payload` | Признак полезной нагрузки (`SYN`, `TUNNEL...`, `UNION...`). |
| `time-window` | Временное окно наблюдения (`short`, `long`). |

### 3.3 `threat-indicator` (индикатор угрозы)

```clips
(deftemplate threat-indicator
  (slot type)
  (slot src)
  (slot dst)
  (slot severity)
  (slot evidence))
```

| Слот | Комментарий |
|---|---|
| `type` | Тип симптома/атаки (`high-rate`, `ddos-attack`, ...). |
| `src` | Источник активности. |
| `dst` | Целевой узел. |
| `severity` | Локальная серьезность индикатора (`medium`/`high`). |
| `evidence` | Краткое текстовое обоснование признака. |

### 3.4 `security-verdict` (финальный вердикт)

```clips
(deftemplate security-verdict
  (slot target)
  (slot action)
  (slot level)
  (slot reason))
```

| Слот | Комментарий |
|---|---|
| `target` | Объект решения (сервис, сеть, SOC, узел). |
| `action` | Рекомендованное действие (`allow`, `block`, `monitor`, `escalate`, `isolate`). |
| `level` | Уровень важности/интенсивности решения. |
| `reason` | Причина принятия решения. |

### 3.5 `analysis-stage` (маркер этапа вывода)

```clips
(deftemplate analysis-stage
  (slot n))
```

| Слот | Комментарий |
|---|---|
| `n` | Номер этапа конвейера правил; управляет порядком исполнения. |

### 3.6 `raw-observation` (нормализованное наблюдение)

```clips
(deftemplate raw-observation
  (slot src)
  (slot dst)
  (slot protocol)
  (slot port)
  (slot rate)
  (slot failed-logins)
  (slot payload))
```

| Слот | Комментарий |
|---|---|
| `src` | Источник события после нормализации. |
| `dst` | Целевой узел после нормализации. |
| `protocol` | Протокол события. |
| `port` | Порт события. |
| `rate` | Интенсивность трафика. |
| `failed-logins` | Количество неуспешных логинов. |
| `payload` | Нормализованный текст полезной нагрузки. |

### 3.7 `aggregate` (агрегированный факт)

```clips
(deftemplate aggregate
  (slot type)
  (slot src)
  (slot dst)
  (slot count))
```

| Слот | Комментарий |
|---|---|
| `type` | Тип агрегата (в модели `indicators-present`). |
| `src` | Источник наблюдения/атаки. |
| `dst` | Целевой узел. |
| `count` | Количество/флаг агрегирования (в текущей модели используется как признак наличия). |

### 3.8 `attack-assessment` (оценка класса атаки)

```clips
(deftemplate attack-assessment
  (slot type)
  (slot src)
  (slot dst)
  (slot level))
```

| Слот | Комментарий |
|---|---|
| `type` | Класс атаки (`ddos`, `brute-force`, `port-scan`, `dns-tunnel`). |
| `src` | Источник атаки. |
| `dst` | Целевой узел. |
| `level` | Оцененный уровень угрозы для этого класса. |

### 3.9 `candidate-action` (кандидатное действие)

```clips
(deftemplate candidate-action
  (slot service)
  (slot action)
  (slot reason))
```

| Слот | Комментарий |
|---|---|
| `service` | Сервис/сегмент, к которому относится мера. |
| `action` | Предлагаемая мера (`block`, `lockout`, `monitor`). |
| `reason` | Причина, почему предложена именно эта мера. |

### 3.10 `decision-flag` (флаг принятого решения)

```clips
(deftemplate decision-flag
  (slot service))
```

| Слот | Комментарий |
|---|---|
| `service` | Сервис, для которого решение уже принято; защищает от повторного выбора. |

### 3.11 `context` (служебный контекст)

```clips
(deftemplate context
  (slot key)
  (slot value))
```

| Слот | Комментарий |
|---|---|
| `key` | Имя маркера состояния (`severity`, `risk`, `report`, `system-state` и т.п.). |
| `value` | Значение маркера (`high`, `ready`, `stable` и т.п.). |

### 3.12 `policy` (базовая политика)

```clips
(deftemplate policy
  (slot service)
  (slot value))
```

| Слот | Комментарий |
|---|---|
| `service` | Сервис, для которого задана политика (`http`, `ssh`, `dns`). |
| `value` | Политика по умолчанию (`allow`). |

## 4. Начальные факты (`deffacts initial-facts`)

Категория: `входные данные`.

Исходный текст (`deffacts`) из `.clp`:

```clips
(deffacts initial-facts
  (analysis-stage (n 1))

  (policy (service http) (value allow))
  (policy (service ssh) (value allow))
  (policy (service dns) (value allow))

  (network-node (id web1) (role web) (os linux) (criticality high) (zone dmz))
  (network-node (id db1)  (role db)  (os linux) (criticality high) (zone internal))
  (network-node (id dns1) (role dns) (os linux) (criticality medium) (zone dmz))

  (traffic-event (src 198.51.100.10) (dst web1) (protocol tcp) (port 80)  (rate high)   (failed-logins 0)  (payload "GET /")           (time-window short))
  (traffic-event (src 198.51.100.11) (dst web1) (protocol tcp) (port 80)  (rate high)   (failed-logins 0)  (payload "GET /index")      (time-window short))
  (traffic-event (src 203.0.113.5)   (dst web1) (protocol tcp) (port 22)  (rate medium) (failed-logins 20) (payload "ssh")             (time-window short))
  (traffic-event (src 203.0.113.5)   (dst web1) (protocol tcp) (port 23)  (rate medium) (failed-logins 0)  (payload "SYN")             (time-window short))
  (traffic-event (src 203.0.113.5)   (dst web1) (protocol tcp) (port 443) (rate medium) (failed-logins 0)  (payload "SYN")             (time-window short))
  (traffic-event (src 192.0.2.77)    (dst dns1) (protocol udp) (port 53)  (rate medium) (failed-logins 0)  (payload "TUNNELDATA")       (time-window short))
  (traffic-event (src 198.51.100.22) (dst web1) (protocol tcp) (port 80)  (rate low)    (failed-logins 0)  (payload "UNION SELECT")     (time-window long))
)
```

Содержимое:
- стартовый stage: `(analysis-stage (n 1))`;
- политики: `http/ssh/dns = allow`;
- три узла (`web1`, `db1`, `dns1`);
- набор тестовых сетевых событий, содержащих признаки разных классов угроз.

Практический смысл: `deffacts` задает демонстрационный сценарий, который позволяет пройти длинную цепочку вывода в одном запуске.

## 5. Карта правил (покрытие каждого `r1...r50`)

## Фаза A. Подготовка и нормализация (`r1-r5`)

Категория фактов: `входные данные` -> `промежуточные`.

| Правило | Что проверяет | Что добавляет | Зачем |
|---|---|---|---|
| `r1-collect-raw` | `traffic-event` на stage 1 | `raw-observation` | Приводит вход к единой форме. |
| `r2-finish-collection` | Есть хотя бы один `raw-observation` | `context raw-collected=yes`, stage 2 | Фиксирует завершение сбора. |
| `r3-verify-nodes` | Есть `network-node` | `context nodes-verified=yes`, stage 3 | Подтверждает наличие описания узлов. |
| `r4-start-normalization` | `nodes-verified=yes` | `context normalization=started`, stage 4 | Маркер начала нормализации. |
| `r5-detect-protocols` | Есть `raw-observation` с протоколом | `context protocols-seen=yes`, stage 5 | Маркер присутствия трафика для анализа. |

Исходный текст правил группы (фрагмент из `.clp`):

```clips
(defrule r1-collect-raw
  (declare (salience 50))
  (analysis-stage (n 1))
  (traffic-event (src ?s) (dst ?d) (protocol ?p) (port ?pt) (rate ?r) (failed-logins ?f) (payload ?pl))
  =>
  (assert (raw-observation (src ?s) (dst ?d) (protocol ?p) (port ?pt) (rate ?r) (failed-logins ?f) (payload ?pl))))

(defrule r2-finish-collection
  ?st <- (analysis-stage (n 1))
  (raw-observation (src ?s))
  =>
  (retract ?st)
  (assert (context (key raw-collected) (value yes)))
  (assert (analysis-stage (n 2))))

(defrule r3-verify-nodes
  ?st <- (analysis-stage (n 2))
  (network-node (id ?id))
  =>
  (retract ?st)
  (assert (context (key nodes-verified) (value yes)))
  (assert (analysis-stage (n 3))))

(defrule r4-start-normalization
  ?st <- (analysis-stage (n 3))
  (context (key nodes-verified) (value yes))
  =>
  (retract ?st)
  (assert (context (key normalization) (value started)))
  (assert (analysis-stage (n 4))))

(defrule r5-detect-protocols
  ?st <- (analysis-stage (n 4))
  (raw-observation (protocol ?p))
  =>
  (retract ?st)
  (assert (context (key protocols-seen) (value yes)))
  (assert (analysis-stage (n 5))))
```

## Фаза B. Детекция угроз (`r6-r15`)

Категория фактов: `промежуточные`.

| Правило | Что проверяет | Что добавляет | Зачем |
|---|---|---|---|
| `r6-detect-high-rate` | `rate high` | `threat-indicator high-rate` | Выделяет симптом аномальной нагрузки. |
| `r7-ddos-indicator` | `high-rate` + порт 80/443 | `threat-indicator ddos-attack` | Подтверждает DDoS-гипотезу. |
| `r8-detect-failed-logins` | `failed-logins >= 10` | `threat-indicator brute-force-symptom` | Фиксирует симптом брутфорса. |
| `r9-bruteforce-indicator` | `brute-force-symptom` | `threat-indicator brute-force-attack` | Подтверждает брутфорс-атаку. |
| `r10-detect-scan-symptom` | `payload` содержит `SYN` | `threat-indicator scan-symptom` | Признак сканирования портов. |
| `r11-portscan-indicator` | `scan-symptom` | `threat-indicator port-scan-attack` | Подтверждение сканирования. |
| `r12-detect-dns-tunnel` | порт 53 + `TUNNEL` в payload | `threat-indicator dns-tunnel-symptom` | Признак DNS-туннеля. |
| `r13-dns-tunnel-indicator` | `dns-tunnel-symptom` | `threat-indicator dns-tunnel-attack` | Подтверждение DNS-туннелирования. |
| `r14-detect-sql-injection` | `UNION` в payload | `threat-indicator app-attack-symptom` | Признак SQL injection. |
| `r15-app-attack-indicator` | `app-attack-symptom` | `threat-indicator app-attack` | Подтверждение прикладной атаки. |

Исходный текст правил группы (фрагмент из `.clp`):

```clips
(defrule r6-detect-high-rate ... (assert (threat-indicator (type high-rate) ...)) (assert (analysis-stage (n 6))))
(defrule r7-ddos-indicator ... (assert (threat-indicator (type ddos-attack) ...)) (assert (analysis-stage (n 7))))
(defrule r8-detect-failed-logins ... (assert (threat-indicator (type brute-force-symptom) ...)) (assert (analysis-stage (n 8))))
(defrule r9-bruteforce-indicator ... (assert (threat-indicator (type brute-force-attack) ...)) (assert (analysis-stage (n 9))))
(defrule r10-detect-scan-symptom ... (test (str-index "SYN" ?pl)) (assert (threat-indicator (type scan-symptom) ...)) (assert (analysis-stage (n 10))))
(defrule r11-portscan-indicator ... (assert (threat-indicator (type port-scan-attack) ...)) (assert (analysis-stage (n 11))))
(defrule r12-detect-dns-tunnel ... (test (str-index "TUNNEL" ?pl)) (assert (threat-indicator (type dns-tunnel-symptom) ...)) (assert (analysis-stage (n 12))))
(defrule r13-dns-tunnel-indicator ... (assert (threat-indicator (type dns-tunnel-attack) ...)) (assert (analysis-stage (n 13))))
(defrule r14-detect-sql-injection ... (test (str-index "UNION" ?pl)) (assert (threat-indicator (type app-attack-symptom) ...)) (assert (analysis-stage (n 14))))
(defrule r15-app-attack-indicator ... (assert (threat-indicator (type app-attack) ...)) (assert (analysis-stage (n 15))))
```

## Фаза C. Оценка серьезности и риска (`r16-r24`)

Категория фактов: `промежуточные`.

| Правило | Что проверяет | Что добавляет | Зачем |
|---|---|---|---|
| `r16-aggregate-indicators` | Любой `threat-indicator` | `aggregate indicators-present` | Унификация наличия индикаторов. |
| `r17-critical-severity` | Индикаторы на узле `criticality high` | `context severity=high` | Повышение серьезности для критичных узлов. |
| `r18-medium-severity` | Нет `severity=high` | `context severity=medium` | Значение по умолчанию. |
| `r19-assess-ddos` | Есть `ddos-attack` | `attack-assessment ddos high` | Оценка DDoS. |
| `r20-assess-bruteforce` | Есть `brute-force-attack` | `attack-assessment brute-force high` | Оценка брутфорса. |
| `r21-assess-portscan` | Есть `port-scan-attack` | `attack-assessment port-scan medium` | Оценка сканирования. |
| `r22-assess-dns-tunnel` | Есть `dns-tunnel-attack` | `attack-assessment dns-tunnel high` | Оценка DNS-туннеля. |
| `r23-compute-risk` | `severity=high` | `context risk=high` | Сводный уровень риска. |
| `r24-map-risk` | Есть `risk` | `context decision-basis=<risk>` | Перенос риска в основу принятия решения. |

Исходный текст правил группы (фрагмент из `.clp`):

```clips
(defrule r16-aggregate-indicators ... (assert (aggregate (type indicators-present) ...)) (assert (analysis-stage (n 16))))
(defrule r17-critical-severity ... (assert (context (key severity) (value high))) (assert (analysis-stage (n 18))))
(defrule r18-medium-severity ... (assert (context (key severity) (value medium))) (assert (analysis-stage (n 18))))
(defrule r19-assess-ddos ... (assert (attack-assessment (type ddos) ... (level high))) (assert (analysis-stage (n 19))))
(defrule r20-assess-bruteforce ... (assert (attack-assessment (type brute-force) ... (level high))) (assert (analysis-stage (n 20))))
(defrule r21-assess-portscan ... (assert (attack-assessment (type port-scan) ... (level medium))) (assert (analysis-stage (n 21))))
(defrule r22-assess-dns-tunnel ... (assert (attack-assessment (type dns-tunnel) ... (level high))) (assert (analysis-stage (n 22))))
(defrule r23-compute-risk ... (assert (context (key risk) (value high))) (assert (analysis-stage (n 23))))
(defrule r24-map-risk ... (assert (context (key decision-basis) (value ?r))) (assert (analysis-stage (n 24))))
```

## Фаза D. Рекомендации и решения по сервисам (`r25-r37`)

Категория фактов: `промежуточные` -> `итоговые`.

| Правило | Что проверяет | Что добавляет | Зачем |
|---|---|---|---|
| `r25-recommend-block-ddos` | `attack-assessment ddos` | `candidate-action http block` | Предварительная мера по HTTP. |
| `r26-recommend-lockout-ssh` | `attack-assessment brute-force` | `candidate-action ssh lockout` | Предварительная мера по SSH. |
| `r27-recommend-monitor-scan` | `attack-assessment port-scan` | `candidate-action net monitor` | Мера мониторинга сети. |
| `r28-recommend-block-dns` | `attack-assessment dns-tunnel` | `candidate-action dns block` | Предварительная мера по DNS. |
| `r29-prepare-http` | stage 28 | `context decision-http=ready` | Подготовка решения по HTTP. |
| `r30-allow-http` | policy allow + нет flag | `security-verdict http allow`, `decision-flag http` | Базовое решение по политике. |
| `r31-deny-http` | ddos + нет flag | `security-verdict http block`, `decision-flag http` | Переопределение policy в сторону защиты. |
| `r32-prepare-ssh` | stage 30 | `context decision-ssh=ready` | Подготовка решения по SSH. |
| `r33-allow-ssh` | policy allow + нет flag | `security-verdict ssh allow`, `decision-flag ssh` | Базовое решение по политике. |
| `r34-deny-ssh` | brute-force + нет flag | `security-verdict ssh block`, `decision-flag ssh` | Переопределение policy при атаке. |
| `r35-prepare-dns` | stage 32 | `context decision-dns=ready` | Подготовка решения по DNS. |
| `r36-allow-dns` | policy allow + нет flag | `security-verdict dns allow`, `decision-flag dns` | Базовое решение по политике. |
| `r37-deny-dns` | dns-tunnel + нет flag | `security-verdict dns block`, `decision-flag dns` | Переопределение policy при угрозе. |

Исходный текст правил группы (фрагмент из `.clp`):

```clips
(defrule r25-recommend-block-ddos ... (assert (candidate-action (service http) (action block) (reason "ddos"))) (assert (analysis-stage (n 25))))
(defrule r26-recommend-lockout-ssh ... (assert (candidate-action (service ssh) (action lockout) (reason "bruteforce"))) (assert (analysis-stage (n 26))))
(defrule r27-recommend-monitor-scan ... (assert (candidate-action (service net) (action monitor) (reason "port-scan"))) (assert (analysis-stage (n 27))))
(defrule r28-recommend-block-dns ... (assert (candidate-action (service dns) (action block) (reason "dns-tunnel"))) (assert (analysis-stage (n 28))))
(defrule r29-prepare-http ... (assert (context (key decision-http) (value ready))) (assert (analysis-stage (n 29))))
(defrule r30-allow-http ... (assert (security-verdict (target http) (action allow) ...)) (assert (decision-flag (service http))) (assert (analysis-stage (n 30))))
(defrule r31-deny-http ... (assert (security-verdict (target http) (action block) ...)) (assert (decision-flag (service http))) (assert (analysis-stage (n 30))))
(defrule r32-prepare-ssh ... (assert (context (key decision-ssh) (value ready))) (assert (analysis-stage (n 31))))
(defrule r33-allow-ssh ... (assert (security-verdict (target ssh) (action allow) ...)) (assert (decision-flag (service ssh))) (assert (analysis-stage (n 32))))
(defrule r34-deny-ssh ... (assert (security-verdict (target ssh) (action block) ...)) (assert (decision-flag (service ssh))) (assert (analysis-stage (n 32))))
(defrule r35-prepare-dns ... (assert (context (key decision-dns) (value ready))) (assert (analysis-stage (n 33))))
(defrule r36-allow-dns ... (assert (security-verdict (target dns) (action allow) ...)) (assert (decision-flag (service dns))) (assert (analysis-stage (n 34))))
(defrule r37-deny-dns ... (assert (security-verdict (target dns) (action block) ...)) (assert (decision-flag (service dns))) (assert (analysis-stage (n 34))))
```

## Фаза E. Консолидация и финализация (`r38-r50`)

Категория фактов: `итоговый результат анализа сети`.

| Правило | Что проверяет | Что добавляет | Зачем |
|---|---|---|---|
| `r38-consolidate-verdicts` | Есть хотя бы один `security-verdict` | `context verdicts=consolidated` | Старт сводного этапа. |
| `r39-prioritize-blocking` | Есть любой `security-verdict action=block` | `context posture=high` | Фиксация высокого режима защиты. |
| `r40-posture-medium` | Нет `posture=high` | `context posture=medium` | Режим по умолчанию. |
| `r41-generate-recommendations` | stage 37 | `security-verdict network monitor` | Общесетевая рекомендация. |
| `r42-escalate-soc` | `posture=high` | `security-verdict soc escalate` | Эскалация в SOC. |
| `r43-final-critical` | Критичный узел + высокий режим | `security-verdict <id> isolate` | Изоляция критичных активов. |
| `r44-log-decision` | stage 40 | `context log=written` | Журналирование решения. |
| `r45-close-session` | stage 41 | `context session=closed` | Закрытие аналитической сессии. |
| `r46-cleanup` | stage 42 | `context cleanup=done` | Завершение служебных действий. |
| `r47-prepare-summary` | stage 43 | `context summary=ready` | Подготовка резюме. |
| `r48-report-ready` | stage 44 | `context report=ready` | Готовность отчета. |
| `r49-mark-complete` | stage 45 | `context inference=complete` | Явная отметка завершения вывода. |
| `r50-final-state` | stage 46 | `context system-state=stable`, stage 47 | Финальная стабилизация состояния. |

Исходный текст правил группы (фрагмент из `.clp`):

```clips
(defrule r38-consolidate-verdicts ... (assert (context (key verdicts) (value consolidated))) (assert (analysis-stage (n 35))))
(defrule r39-prioritize-blocking ... (assert (context (key posture) (value high))) (assert (analysis-stage (n 37))))
(defrule r40-posture-medium ... (assert (context (key posture) (value medium))) (assert (analysis-stage (n 37))))
(defrule r41-generate-recommendations ... (assert (security-verdict (target network) (action monitor) ...)) (assert (analysis-stage (n 38))))
(defrule r42-escalate-soc ... (assert (security-verdict (target soc) (action escalate) ...)) (assert (analysis-stage (n 39))))
(defrule r43-final-critical ... (assert (security-verdict (target ?id) (action isolate) ...)) (assert (analysis-stage (n 40))))
(defrule r44-log-decision ... (assert (context (key log) (value written))) (assert (analysis-stage (n 41))))
(defrule r45-close-session ... (assert (context (key session) (value closed))) (assert (analysis-stage (n 42))))
(defrule r46-cleanup ... (assert (context (key cleanup) (value done))) (assert (analysis-stage (n 43))))
(defrule r47-prepare-summary ... (assert (context (key summary) (value ready))) (assert (analysis-stage (n 44))))
(defrule r48-report-ready ... (assert (context (key report) (value ready))) (assert (analysis-stage (n 45))))
(defrule r49-mark-complete ... (assert (context (key inference) (value complete))) (assert (analysis-stage (n 46))))
(defrule r50-final-state ... (assert (context (key system-state) (value stable))) (assert (analysis-stage (n 47))))
```

## 6. Как в системе решаются конфликты правил

Критичные конфликтные пары:
- `r30` (allow http) vs `r31` (deny http)
- `r33` (allow ssh) vs `r34` (deny ssh)
- `r36` (allow dns) vs `r37` (deny dns)

Механизм:
- у deny-правил `salience 20`, у allow-правил `salience 0`;
- обе стороны проверяют `(not (decision-flag ...))`;
- победившее правило ставит `decision-flag`, блокируя альтернативу.

Это классическое разрешение конфликта в продукционной модели CLIPS `[Частиков и др., 2003, гл. 6.3-6.4]`.

## 7. Что важно знать новому участнику (операционно)

1. Для запуска в корне проекта:
```bash
printf "(clear)\n(load \"./network_security_assessment.clp\")\n(reset)\n(watch rules)\n(run)\n(facts)\n(exit)\n" | clips
```

2. Типовая картина успешного прогона:
- загрузка `TRUE`;
- длинная цепочка `FIRE ...`;
- итоговые `security-verdict` и `context system-state=stable`.

3. Где смотреть примеры и разбор вывода:
- `./notes/current_es_status.md`
- `./notes/mlv_run_example.md`

## 8. Словарь терминов CLIPS для быстрого старта

- `deftemplate`: шаблон фактов (структура слотов).
- `deffacts`: стартовый набор фактов (активируется через `reset`).
- `defrule`: продукционное правило `LHS => RHS`.
- `LHS` (левая часть): условия срабатывания (patterns, `test`, `not`).
- `RHS` (правая часть): действия (`assert`, `retract` и т.д.).
- `assert`: добавить факт в рабочую память.
- `retract`: удалить факт из рабочей памяти.
- `salience`: приоритет правила в конфликтном наборе.
- `test`: процедурная проверка в условиях.
- `not`: условие отсутствия факта.
- `?var`: переменная сопоставления.
- `?x&:(predicate ...)`: ограничение на переменную предикатом.

Опора: `[Частиков и др., 2003, гл. 4 (шаблоны/факты), гл. 5 (факты), гл. 6 (правила/конфликты/LHS)]`.

## 9. Важные замечания по текущей реализации

- `r18-medium-severity` ожидает `analysis-stage (n 17)`, но после `r17` выставляется сразу stage `18`.
  Практический эффект: `r18` в текущем потоке недостижимо.
- `r40-posture-medium` ожидает stage `36`, но `r39` переводит в stage `37`.
  Практический эффект: `r40` в текущем потоке недостижимо.

Для onboarding это важно: при чтении модели не считать эти правила частью реально исполняемой ветки без дополнительной корректировки stage-переходов.

## 10. Appendix: исходный текст из `.clp` (дословно)

Ниже приведены буквальные фрагменты из `./network_security_assessment.clp` без сокращений.

### 10.1 `deffacts initial-facts`
```clips
(deffacts initial-facts
  (analysis-stage (n 1))

  (policy (service http) (value allow))
  (policy (service ssh) (value allow))
  (policy (service dns) (value allow))

  (network-node (id web1) (role web) (os linux) (criticality high) (zone dmz))
  (network-node (id db1)  (role db)  (os linux) (criticality high) (zone internal))
  (network-node (id dns1) (role dns) (os linux) (criticality medium) (zone dmz))

  (traffic-event (src 198.51.100.10) (dst web1) (protocol tcp) (port 80)  (rate high)   (failed-logins 0)  (payload "GET /")           (time-window short))
  (traffic-event (src 198.51.100.11) (dst web1) (protocol tcp) (port 80)  (rate high)   (failed-logins 0)  (payload "GET /index")      (time-window short))
  (traffic-event (src 203.0.113.5)   (dst web1) (protocol tcp) (port 22)  (rate medium) (failed-logins 20) (payload "ssh")             (time-window short))
  (traffic-event (src 203.0.113.5)   (dst web1) (protocol tcp) (port 23)  (rate medium) (failed-logins 0)  (payload "SYN")             (time-window short))
  (traffic-event (src 203.0.113.5)   (dst web1) (protocol tcp) (port 443) (rate medium) (failed-logins 0)  (payload "SYN")             (time-window short))
  (traffic-event (src 192.0.2.77)    (dst dns1) (protocol udp) (port 53)  (rate medium) (failed-logins 0)  (payload "TUNNELDATA")       (time-window short))
  (traffic-event (src 198.51.100.22) (dst web1) (protocol tcp) (port 80)  (rate low)    (failed-logins 0)  (payload "UNION SELECT")     (time-window long))
)
```

### 10.2 Фаза A (`r1-r5`)
```clips
(defrule r1-collect-raw
  (declare (salience 50))
  (analysis-stage (n 1))
  (traffic-event (src ?s) (dst ?d) (protocol ?p) (port ?pt) (rate ?r) (failed-logins ?f) (payload ?pl))
  =>
  (assert (raw-observation (src ?s) (dst ?d) (protocol ?p) (port ?pt) (rate ?r) (failed-logins ?f) (payload ?pl)))
)

; 2. Завершение этапа сбора и переход к анализу узлов
(defrule r2-finish-collection
  ?st <- (analysis-stage (n 1))
  (raw-observation (src ?s))
  =>
  (retract ?st)
  (assert (context (key raw-collected) (value yes)))
  (assert (analysis-stage (n 2)))
)

; 3. Проверка наличия описаний узлов сети
(defrule r3-verify-nodes
  ?st <- (analysis-stage (n 2))
  (network-node (id ?id))
  =>
  (retract ?st)
  (assert (context (key nodes-verified) (value yes)))
  (assert (analysis-stage (n 3)))
)

; 4. Фиксация факта начала нормализации
(defrule r4-start-normalization
  ?st <- (analysis-stage (n 3))
  (context (key nodes-verified) (value yes))
  =>
  (retract ?st)
  (assert (context (key normalization) (value started)))
  (assert (analysis-stage (n 4)))
)

; 5. Подтверждение наличия TCP/UDP-трафика
(defrule r5-detect-protocols
  ?st <- (analysis-stage (n 4))
  (raw-observation (protocol ?p))
  =>
  (retract ?st)
  (assert (context (key protocols-seen) (value yes)))
  (assert (analysis-stage (n 5)))
)
```

### 10.3 Фаза B (`r6-r15`)
```clips
(defrule r6-detect-high-rate
  ?st <- (analysis-stage (n 5))
  (raw-observation (rate high) (src ?s) (dst ?d))
  =>
  (retract ?st)
  (assert (threat-indicator (type high-rate) (src ?s) (dst ?d) (severity medium) (evidence "high-rate")))
  (assert (analysis-stage (n 6)))
)

; 7. Преобразование высокой интенсивности в индикатор DDoS
(defrule r7-ddos-indicator
  ?st <- (analysis-stage (n 6))
  (threat-indicator (type high-rate) (src ?s) (dst ?d))
  (raw-observation (dst ?d) (port ?pt&:(or (= ?pt 80) (= ?pt 443))))
  =>
  (retract ?st)
  (assert (threat-indicator (type ddos-attack) (src ?s) (dst ?d) (severity high) (evidence "many-requests")))
  (assert (analysis-stage (n 7)))
)

; 8. Выявление множества неуспешных логинов
(defrule r8-detect-failed-logins
  ?st <- (analysis-stage (n 7))
  (raw-observation (src ?s) (dst ?d) (failed-logins ?f&:(>= ?f 10)))
  =>
  (retract ?st)
  (assert (threat-indicator (type brute-force-symptom) (src ?s) (dst ?d) (severity medium) (evidence "failed-logins")))
  (assert (analysis-stage (n 8)))
)

; 9. Преобразование симптома в атаку брутфорса
(defrule r9-bruteforce-indicator
  ?st <- (analysis-stage (n 8))
  (threat-indicator (type brute-force-symptom) (src ?s) (dst ?d))
  =>
  (retract ?st)
  (assert (threat-indicator (type brute-force-attack) (src ?s) (dst ?d) (severity high) (evidence "ssh-bruteforce")))
  (assert (analysis-stage (n 9)))
)

; 10. Обнаружение сигналов сканирования портов
(defrule r10-detect-scan-symptom
  ?st <- (analysis-stage (n 9))
  (raw-observation (src ?s) (dst ?d) (payload ?pl))
  (test (str-index "SYN" ?pl))
  =>
  (retract ?st)
  (assert (threat-indicator (type scan-symptom) (src ?s) (dst ?d) (severity medium) (evidence "syn-probes")))
  (assert (analysis-stage (n 10)))
)

; 11. Преобразование симптома в атаку сканирования
(defrule r11-portscan-indicator
  ?st <- (analysis-stage (n 10))
  (threat-indicator (type scan-symptom) (src ?s) (dst ?d))
  =>
  (retract ?st)
  (assert (threat-indicator (type port-scan-attack) (src ?s) (dst ?d) (severity medium) (evidence "port-scan")))
  (assert (analysis-stage (n 11)))
)

; 12. Выявление туннелирования через DNS
(defrule r12-detect-dns-tunnel
  ?st <- (analysis-stage (n 11))
  (raw-observation (src ?s) (dst ?d) (port 53) (payload ?pl))
  (test (str-index "TUNNEL" ?pl))
  =>
  (retract ?st)
  (assert (threat-indicator (type dns-tunnel-symptom) (src ?s) (dst ?d) (severity medium) (evidence "dns-tunnel")))
  (assert (analysis-stage (n 12)))
)

; 13. Подтверждение атаки DNS-туннелирования
(defrule r13-dns-tunnel-indicator
  ?st <- (analysis-stage (n 12))
  (threat-indicator (type dns-tunnel-symptom) (src ?s) (dst ?d))
  =>
  (retract ?st)
  (assert (threat-indicator (type dns-tunnel-attack) (src ?s) (dst ?d) (severity high) (evidence "dns-exfil")))
  (assert (analysis-stage (n 13)))
)

; 14. Поиск признаков SQL-инъекций
(defrule r14-detect-sql-injection
  ?st <- (analysis-stage (n 13))
  (raw-observation (src ?s) (dst ?d) (payload ?pl))
  (test (str-index "UNION" ?pl))
  =>
  (retract ?st)
  (assert (threat-indicator (type app-attack-symptom) (src ?s) (dst ?d) (severity medium) (evidence "sql-injection")))
  (assert (analysis-stage (n 14)))
)

; 15. Подтверждение прикладной атаки
(defrule r15-app-attack-indicator
  ?st <- (analysis-stage (n 14))
  (threat-indicator (type app-attack-symptom) (src ?s) (dst ?d))
  =>
  (retract ?st)
  (assert (threat-indicator (type app-attack) (src ?s) (dst ?d) (severity high) (evidence "web-attack")))
  (assert (analysis-stage (n 15)))
)
```

### 10.4 Фаза C (`r16-r24`)
```clips
(defrule r16-aggregate-indicators
  ?st <- (analysis-stage (n 15))
  (threat-indicator (type ?t) (src ?s) (dst ?d))
  =>
  (retract ?st)
  (assert (aggregate (type indicators-present) (src ?s) (dst ?d) (count 1)))
  (assert (analysis-stage (n 16)))
)

; 17. Повышение серьёзности для критичных узлов
(defrule r17-critical-severity
  ?st <- (analysis-stage (n 16))
  (aggregate (type indicators-present) (dst ?d))
  (network-node (id ?d) (criticality high))
  =>
  (retract ?st)
  (assert (context (key severity) (value high)))
  (assert (analysis-stage (n 18)))
)

; 18. Установка средней серьёзности по умолчанию
(defrule r18-medium-severity
  ?st <- (analysis-stage (n 17))
  (not (context (key severity) (value high)))
  =>
  (retract ?st)
  (assert (context (key severity) (value medium)))
  (assert (analysis-stage (n 18)))
)

; 19. Формирование оценки DDoS
(defrule r19-assess-ddos
  ?st <- (analysis-stage (n 18))
  (threat-indicator (type ddos-attack) (src ?s) (dst ?d))
  =>
  (retract ?st)
  (assert (attack-assessment (type ddos) (src ?s) (dst ?d) (level high)))
  (assert (analysis-stage (n 19)))
)

; 20. Формирование оценки брутфорса
(defrule r20-assess-bruteforce
  ?st <- (analysis-stage (n 19))
  (threat-indicator (type brute-force-attack) (src ?s) (dst ?d))
  =>
  (retract ?st)
  (assert (attack-assessment (type brute-force) (src ?s) (dst ?d) (level high)))
  (assert (analysis-stage (n 20)))
)

; 21. Формирование оценки сканирования портов
(defrule r21-assess-portscan
  ?st <- (analysis-stage (n 20))
  (threat-indicator (type port-scan-attack) (src ?s) (dst ?d))
  =>
  (retract ?st)
  (assert (attack-assessment (type port-scan) (src ?s) (dst ?d) (level medium)))
  (assert (analysis-stage (n 21)))
)

; 22. Формирование оценки DNS-туннеля
(defrule r22-assess-dns-tunnel
  ?st <- (analysis-stage (n 21))
  (threat-indicator (type dns-tunnel-attack) (src ?s) (dst ?d))
  =>
  (retract ?st)
  (assert (attack-assessment (type dns-tunnel) (src ?s) (dst ?d) (level high)))
  (assert (analysis-stage (n 22)))
)

; 23. Вычисление уровня риска
(defrule r23-compute-risk
  ?st <- (analysis-stage (n 22))
  (context (key severity) (value high))
  =>
  (retract ?st)
  (assert (context (key risk) (value high)))
  (assert (analysis-stage (n 23)))
)

; 24. Преобразование риска в базу решения
(defrule r24-map-risk
  ?st <- (analysis-stage (n 23))
  (context (key risk) (value ?r))
  =>
  (retract ?st)
  (assert (context (key decision-basis) (value ?r)))
  (assert (analysis-stage (n 24)))
)
```

### 10.5 Фаза D (`r25-r37`)
```clips
(defrule r25-recommend-block-ddos
  ?st <- (analysis-stage (n 24))
  (attack-assessment (type ddos) (dst ?d))
  =>
  (retract ?st)
  (assert (candidate-action (service http) (action block) (reason "ddos")))
  (assert (analysis-stage (n 25)))
)

; 26. Рекомендация блокировки/локдауна для брутфорса
(defrule r26-recommend-lockout-ssh
  ?st <- (analysis-stage (n 25))
  (attack-assessment (type brute-force) (dst ?d))
  =>
  (retract ?st)
  (assert (candidate-action (service ssh) (action lockout) (reason "bruteforce")))
  (assert (analysis-stage (n 26)))
)

; 27. Рекомендация мониторинга для сканирования портов
(defrule r27-recommend-monitor-scan
  ?st <- (analysis-stage (n 26))
  (attack-assessment (type port-scan) (dst ?d))
  =>
  (retract ?st)
  (assert (candidate-action (service net) (action monitor) (reason "port-scan")))
  (assert (analysis-stage (n 27)))
)

; 28. Рекомендация блокировки для DNS-туннеля
(defrule r28-recommend-block-dns
  ?st <- (analysis-stage (n 27))
  (attack-assessment (type dns-tunnel) (dst ?d))
  =>
  (retract ?st)
  (assert (candidate-action (service dns) (action block) (reason "dns-tunnel")))
  (assert (analysis-stage (n 28)))
)

; 29. Подготовка решения по HTTP
(defrule r29-prepare-http
  ?st <- (analysis-stage (n 28))
  =>
  (retract ?st)
  (assert (context (key decision-http) (value ready)))
  (assert (analysis-stage (n 29)))
)

; 30. Разрешение HTTP по политике (конфликтное правило)
(defrule r30-allow-http
  (declare (salience 0))
  ?st <- (analysis-stage (n 29))
  (policy (service http) (value allow))
  (not (decision-flag (service http)))
  =>
  (retract ?st)
  (assert (security-verdict (target http) (action allow) (level medium) (reason "policy-allow")))
  (assert (decision-flag (service http)))
  (assert (analysis-stage (n 30)))
)

; 31. Запрет HTTP при DDoS (конфликтное правило с высоким приоритетом)
(defrule r31-deny-http
  (declare (salience 20))
  ?st <- (analysis-stage (n 29))
  (threat-indicator (type ddos-attack) (dst ?d))
  (not (decision-flag (service http)))
  =>
  (retract ?st)
  (assert (security-verdict (target http) (action block) (level high) (reason "ddos")))
  (assert (decision-flag (service http)))
  (assert (analysis-stage (n 30)))
)

; 32. Подготовка решения по SSH
(defrule r32-prepare-ssh
  ?st <- (analysis-stage (n 30))
  =>
  (retract ?st)
  (assert (context (key decision-ssh) (value ready)))
  (assert (analysis-stage (n 31)))
)

; 33. Разрешение SSH по политике (конфликтное правило)
(defrule r33-allow-ssh
  (declare (salience 0))
  ?st <- (analysis-stage (n 31))
  (policy (service ssh) (value allow))
  (not (decision-flag (service ssh)))
  =>
  (retract ?st)
  (assert (security-verdict (target ssh) (action allow) (level medium) (reason "policy-allow")))
  (assert (decision-flag (service ssh)))
  (assert (analysis-stage (n 32)))
)

; 34. Запрет SSH при брутфорсе (конфликтное правило с высоким приоритетом)
(defrule r34-deny-ssh
  (declare (salience 20))
  ?st <- (analysis-stage (n 31))
  (threat-indicator (type brute-force-attack) (dst ?d))
  (not (decision-flag (service ssh)))
  =>
  (retract ?st)
  (assert (security-verdict (target ssh) (action block) (level high) (reason "bruteforce")))
  (assert (decision-flag (service ssh)))
  (assert (analysis-stage (n 32)))
)

; 35. Подготовка решения по DNS
(defrule r35-prepare-dns
  ?st <- (analysis-stage (n 32))
  =>
  (retract ?st)
  (assert (context (key decision-dns) (value ready)))
  (assert (analysis-stage (n 33)))
)

; 36. Разрешение DNS по политике (конфликтное правило)
(defrule r36-allow-dns
  (declare (salience 0))
  ?st <- (analysis-stage (n 33))
  (policy (service dns) (value allow))
  (not (decision-flag (service dns)))
  =>
  (retract ?st)
  (assert (security-verdict (target dns) (action allow) (level medium) (reason "policy-allow")))
  (assert (decision-flag (service dns)))
  (assert (analysis-stage (n 34)))
)

; 37. Запрет DNS при туннелировании (конфликтное правило с высоким приоритетом)
(defrule r37-deny-dns
  (declare (salience 20))
  ?st <- (analysis-stage (n 33))
  (threat-indicator (type dns-tunnel-attack) (dst ?d))
  (not (decision-flag (service dns)))
  =>
  (retract ?st)
  (assert (security-verdict (target dns) (action block) (level high) (reason "dns-tunnel")))
  (assert (decision-flag (service dns)))
  (assert (analysis-stage (n 34)))
)
```

### 10.6 Фаза E (`r38-r50`)
```clips
(defrule r38-consolidate-verdicts
  ?st <- (analysis-stage (n 34))
  (security-verdict (target ?t))
  =>
  (retract ?st)
  (assert (context (key verdicts) (value consolidated)))
  (assert (analysis-stage (n 35)))
)

; 39. Приоритизация блокировок при наличии запретов
(defrule r39-prioritize-blocking
  ?st <- (analysis-stage (n 35))
  (security-verdict (action block))
  =>
  (retract ?st)
  (assert (context (key posture) (value high)))
  (assert (analysis-stage (n 37)))
)

; 40. Установка среднего режима при отсутствии блокировок
(defrule r40-posture-medium
  ?st <- (analysis-stage (n 36))
  (not (context (key posture) (value high)))
  =>
  (retract ?st)
  (assert (context (key posture) (value medium)))
  (assert (analysis-stage (n 37)))
)

; 41. Формирование рекомендаций по мониторингу
(defrule r41-generate-recommendations
  ?st <- (analysis-stage (n 37))
  =>
  (retract ?st)
  (assert (security-verdict (target network) (action monitor) (level medium) (reason "continuous-monitoring")))
  (assert (analysis-stage (n 38)))
)

; 42. Эскалация в SOC при высоком режиме
(defrule r42-escalate-soc
  ?st <- (analysis-stage (n 38))
  (context (key posture) (value high))
  =>
  (retract ?st)
  (assert (security-verdict (target soc) (action escalate) (level high) (reason "high-risk")))
  (assert (analysis-stage (n 39)))
)

; 43. Итоговое решение по критичным узлам
(defrule r43-final-critical
  ?st <- (analysis-stage (n 39))
  (network-node (id ?id) (criticality high))
  (context (key posture) (value high))
  =>
  (retract ?st)
  (assert (security-verdict (target ?id) (action isolate) (level high) (reason "critical-asset")))
  (assert (analysis-stage (n 40)))
)

; 44. Журналирование принятого решения
(defrule r44-log-decision
  ?st <- (analysis-stage (n 40))
  =>
  (retract ?st)
  (assert (context (key log) (value written)))
  (assert (analysis-stage (n 41)))
)

; 45. Закрытие аналитической сессии
(defrule r45-close-session
  ?st <- (analysis-stage (n 41))
  =>
  (retract ?st)
  (assert (context (key session) (value closed)))
  (assert (analysis-stage (n 42)))
)

; 46. Очистка временных следов анализа
(defrule r46-cleanup
  ?st <- (analysis-stage (n 42))
  =>
  (retract ?st)
  (assert (context (key cleanup) (value done)))
  (assert (analysis-stage (n 43)))
)

; 47. Подготовка итогового резюме
(defrule r47-prepare-summary
  ?st <- (analysis-stage (n 43))
  =>
  (retract ?st)
  (assert (context (key summary) (value ready)))
  (assert (analysis-stage (n 44)))
)

; 48. Формирование отчёта
(defrule r48-report-ready
  ?st <- (analysis-stage (n 44))
  =>
  (retract ?st)
  (assert (context (key report) (value ready)))
  (assert (analysis-stage (n 45)))
)

; 49. Отметка о завершении вывода
(defrule r49-mark-complete
  ?st <- (analysis-stage (n 45))
  =>
  (retract ?st)
  (assert (context (key inference) (value complete)))
  (assert (analysis-stage (n 46)))
)

; 50. Финальная фиксация состояния системы
(defrule r50-final-state
  ?st <- (analysis-stage (n 46))
  =>
  (retract ?st)
  (assert (context (key system-state) (value stable)))
  (assert (analysis-stage (n 47)))
)
```

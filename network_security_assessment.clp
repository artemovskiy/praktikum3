;========================
; ШАБЛОНЫ ДАННЫХ
;========================
(deftemplate network-node
  (slot id)
  (slot role)
  (slot os)
  (slot criticality)
  (slot zone))

(deftemplate traffic-event
  (slot src)
  (slot dst)
  (slot protocol)
  (slot port)
  (slot rate)
  (slot failed-logins)
  (slot payload)
  (slot time-window))

(deftemplate threat-indicator
  (slot type)
  (slot src)
  (slot dst)
  (slot severity)
  (slot evidence))

(deftemplate security-verdict
  (slot target)
  (slot action)
  (slot level)
  (slot reason))

(deftemplate analysis-stage
  (slot n))

(deftemplate raw-observation
  (slot src)
  (slot dst)
  (slot protocol)
  (slot port)
  (slot rate)
  (slot failed-logins)
  (slot payload))

(deftemplate aggregate
  (slot type)
  (slot src)
  (slot dst)
  (slot count))

(deftemplate attack-assessment
  (slot type)
  (slot src)
  (slot dst)
  (slot level))

(deftemplate candidate-action
  (slot service)
  (slot action)
  (slot reason))

(deftemplate decision-flag
  (slot service))

(deftemplate context
  (slot key)
  (slot value))

(deftemplate policy
  (slot service)
  (slot value))

;========================
; НАЧАЛЬНЫЕ ФАКТЫ
;========================
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

;========================
; БАЗА ПРАВИЛ (РОВНО 50)
;========================

; 1. Сбор сырых наблюдений по каждому событию трафика
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

; 6. Выявление высокой интенсивности трафика
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

; 16. Агрегация наличия индикаторов
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

; 25. Рекомендация блокировки для DDoS
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

; 38. Консолидация частных вердиктов
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

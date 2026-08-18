Общий вид:
```json
{
  "vulnerability_id": "some_id",
  "title": "SQL Injection in auth component", // откуда брать?

  // Ключевой блок статусов
  "status": "checked",    // Только "unchecked" или "checked"
  "verdict": "confirmed",  // null (если unchecked), "confirmed" или "unconfirmed"
  "confirmed_by": "pentest-agent",    // null, "dast", "pentest-agent"

  // может быть null, если угрозу нашел только даст
  "sast": {
	... //какая то инфа от саста. Может быть пустым
	
	"score": 8.1 // результат скоринг-агента
  },
  
  
	
  // Детализация проверок для людей(формат report просто для примера)
  // Поля могут быть null
  "verification_history": {
    "dast": {
      "run_executed": true,
      "verdict_output": "unconfirmed", 
      "report": {
        "tool_name": "OWASP ZAP",
        "action_taken": "Отправлен атакующий вектор ' OR 1=1 -- в эндпоинт /api/v1/auth",
        "result_details": "Сервер вернул 403 Forbidden. Скорее всего, сработал WAF на базовый паттерн."
      }
    },
    "pentest": {
      "run_executed": true,
      "verdict_output": "confirmed",   // Агент смог! Снимаем unchecked, ставим checked + confirmed
      "human_report": {
        "agent_id": "agent-007",
        "action_taken": "Проведен обход WAF с использованием double URL-encoding payload.",
        "result_details": "Успешно выполнена инъекция. Извлечена версия БД: PostgreSQL 15.2. Получен флаг: Hg1#7b2d183f-4e8a-4993 Уязвимость подтверждена."
      }
    }
  }
}
```

## спецификация Vulnerability Lifecycle Schema (VLS):

Назначение документа: Описание внутренней структуры данных единого объекта уязвимости, используемого для сквозного отслеживания на этапах статического (SAST), динамического (DAST) и пентест анализа.

---

## 1. Схема состояний (Конечный автомат)

Объект уязвимости строго следует правилам консистентности. Сочетание внутренних технических статусов и бизнес-вердиктов для ИБ-специалистов(людей которые аутпут читают) регулируется следующей матрицей переходов:

| Текущий `status` | Возможный `verdict` | Возможный `confirmed_by`                                               | Описание состояния                                                                                                                                                                                                                                                                                          |
| ---------------- | ------------------- | ---------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `unchecked`      | `null`              | `null`                                                                 | В работе. <br>Уязвимость обнаружена сканером, но еще не подтверждена ни одним динамическим методом. Обязательна для дальнейшей обработки пайплайном.<br>Не должен доходить до финального аутпута приложения(за исключением случаев преждевременной остановки).                                              |
| `checked`        | `confirmed`         | `dast` / `pentest-agent` (если каким то образом их несколько – массив) | Подтверждено. <br>Уязвимость успешно воспроизведена в тестовой среде. <br>Поле `confirmed_by` указывает на инструмент(-ы), предоставившие пруфы. <br>Внутренний флаг проверки снят => дальнейшие инструменты проверки игнорируют объект(уязвимость просто не подается пентестеру, если ее подтвердил DAST). |
| `checked`        | `unconfirmed`       | `null`                                                                 | Ложное срабатывание / Закрыто. <br>Статус должен быть гарантировано присвоен на последнем этапе работы приложения для всех unchecked объектов. <br>Означает, что все доступные динамические методы (DAST и Пентест-агент) попытались воспроизвести уязвимость, но получили отказ. Проверка закрыта.         |

---

## 2. Спецификация полей JSON-объекта

Каждая запись уязвимости представляет собой JSON-документ со следующей структурой:

## 2.1. Корневые метаданные управления

- `id` _(string, UUID)_: Уникальный идентификатор уязвимости в рамках системы.
- `title` _(string)_: Краткое человекочитаемое название уязвимости (например, _"SQL Injection via User Input"_).
- `status` _(enum: "unchecked", "checked")_: Технический статус обработки записи в пайплайне.
- `verdict` _(enum: "confirmed", "unconfirmed", null)_: Финальный вердикт безопасности для аналитика.
- `confirmed_by` _(enum: "dast", "pentest-agent", null)_: Источник успешного подтверждения уязвимости.

## 2.2. Блок SAST (`sast`) — Первичная находка

(все, кроме score – гипотетическое для примера. Зависит от инструмента)

_Заполняется результатом работы Semgrep. Может быть `null`, если уязвимость впервые обнаружена на этапе DAST._

- `tool` _(string)_: Имя сканера (всегда `"semgrep"`).
- `rule_id` _(string)_: Иерархический ID правила Semgrep.
- `file_path` _(string)_: Путь к уязвимому файлу относительно корня репозитория.
- `line` _(integer)_: Номер строки в коде.
- ...
- `score` _(float)_: Базовый скоринг опасности (например, CVSS).

## 2.3. Журнал верификации (`verification_history`)

_Содержит подобъекты `dast` и `pentest` с логами для ИБ-специалистов._

Каждый шаг (`dast` и `pentest`) содержит:

- `run_executed` _(boolean)_: Была ли запущена проверка данным методом.
- `verdict_output` _(enum: "confirmed", "unconfirmed", "not_tested")_: Промежуточный результат конкретного шага.
- `human_report` _(object, null)_: Лог для человека. Содержит поля:
    
    - `executor_name` _(string)_: Имя инструмента или ID агента.
    - `action_taken` _(string)_: Описание того, что именно делал тестер (какой вектор отправлял, какие обходы WAF применял).
    - `result_details` _(string)_: Технический отчет о результате
    

---

## 3. Эталонный JSON-пример (заполнение по ходу работы)

Ниже по этапно приведен пример уязвимости, которая прошла все этапы: Semgrep её нашел, DAST не смог пробить защиту (но флаг `unchecked` не снялся), а Пентест-агент успешно дожал уязвимость, переведя её в финальный статус.

##### ЭТАП 1: получен результат SAST, проведен Скоринг(фактически объект полноценно собирается перед входом в P-A, на основе данных от скоринга и DAST).
```json
// 
{
  "$schema": "?",
  vulnerability_id: "popa",
  "title": "bolit",
  
  "status": "unchecked",
  "verdict": null,
  "confirmed_by": null,
  
  "sast": {
    "tool": "semgrep",
    "rule_id": "java.lang.security.audit.sql-injection.after-java-poopaccino",
    "file_path": "src/main/java/com/auth/UserService.java",
    "line": 42,
    "score": 8.2
  },
  
  "verification_history": {
    "dast": {
      "run_executed": false,
      "verdict_output": "not_tested",
      "human_report": null
    },
    "pentest": {
      "run_executed": false,
      "verdict_output": "not_tested",
      "human_report": null
  }
}
```

##### ЭТАП 2: Получен результат DAST, удалось сопоставить с уязвимостью из саст.
```json
// 
{
  "$schema": "?",
  vulnerability_id: "popa",
  "title": "bolit",
  
  "status": "unchecked",
  "verdict": null,
  "confirmed_by": null,
  
  "sast": {
    "tool": "semgrep",
    "rule_id": "java.lang.security.audit.sql-injection.after-java-poopaccino",
    "file_path": "src/main/java/com/auth/UserService.java",
    "line": 42,
    "score": 8.2
  },
  
  "verification_history": {
    "dast": {
      "run_executed": true,
      "verdict_output": "unconfirmed",
      "human_report": {
        "executor_name": "OWASP ZAP Core",
        "action_taken": "Отправлен классический SQL-payload \"' OR '1'='1\" в POST-параметр 'username'.",
        "result_details": "Da vrode ne bolit."
      }
    },
    "pentest": {
      "run_executed": false,
      "verdict_output": "not_tested",
      "human_report": null
  }
}
```

##### ЭТАП 3: Финальный аутпут. Пентестер провел check-сессию, кинул запрос для установки состояния. 

```json
// 
{
  "$schema": "?",
  vulnerability_id: "popa",
  "title": "bolit",
  
  "status": "checked",
  "verdict": "confirmed",
  "confirmed_by": "pentest-agent",
  
  "sast": {
    "tool": "semgrep",
    "rule_id": "java.lang.security.audit.sql-injection.after-java-poopaccino",
    "file_path": "src/main/java/com/auth/UserService.java",
    "line": 42,
    "score": 8.2
  },
  
  "verification_history": {
    "dast": {
      "run_executed": true,
      "verdict_output": "unconfirmed",
      "human_report": {
        "executor_name": "OWASP ZAP Core",
        "action_taken": "Отправлен классический SQL-payload \"' OR '1'='1\" в POST-параметр 'username'.",
        "result_details": "Da vrode ne bolit."
      }
    },
    "pentest": {
      "run_executed": true,
      "verdict_output": "confirmed",
      "human_report": {
        "executor_name": "Pentest-Agent-007",
        "action_taken": "Произведен автоматический обход WAF с использованием Double URL Encoding payload (%2527%2520OR%25201%253D1).",
        "result_details": "Не, все таки болит."
      }
    }
  }
}
```


---

##### Если DAST подтвердил уязвимость, то на выход у нас подается такая дичь:

```json
// 
{
  "$schema": "?",
  vulnerability_id: "popa",
  "title": "bolit",
  
  "status": "checked",
  "verdict": "confirmed",
  "confirmed_by": "dast",
  
  "sast": {
    "tool": "semgrep",
    "rule_id": "java.lang.security.audit.sql-injection.after-java-poopaccino",
    "file_path": "src/main/java/com/auth/UserService.java",
    "line": 42,
    "score": 8.2
  },
  
  "verification_history": {
    "dast": {
      "run_executed": true,
      "verdict_output": "confirmed",
      "human_report": {
        "executor_name": "OWASP ZAP Core",
        "action_taken": "Отправлен классический SQL-payload \"' OR '1'='1\" в POST-параметр 'username'.",
        "result_details": "Da vrode bolit."
      }
    },
    "pentest": {
      "run_executed": false,
      "verdict_output": "not_tested",
      "human_report": null
  }
}
```

##### или может быть случай без SAST(тогда и пентестера как будто хер знает как применять):

```json
// 
{
  "$schema": "?",
  vulnerability_id: "popa",
  "title": "bolit",
  
  "status": "checked",
  "verdict": "confirmed",
  "confirmed_by": "dast",
  
  "sast": null,
  
  "verification_history": {
    "dast": {
      "run_executed": true,
      "verdict_output": "confirmed",
      "human_report": {
        "executor_name": "OWASP ZAP Core",
        "action_taken": "Отправлен классический SQL-payload \"' OR '1'='1\" в POST-параметр 'username'.",
        "result_details": "Da vrode bolit."
      }
    },
    "pentest": {
      "run_executed": false,
      "verdict_output": "not_tested",
      "human_report": null
  }
}
```
---

## 4. Бизнес-логика изменения полей (Пайплайн)

1. Инициализация (Выход Semgrep):
    
    - Создается объект. `status = "unchecked"`, `verdict = null`, `confirmed_by = null`.
    
2. Обработка DAST:
    
    - Если DAST подтверждает уязвимость → `status = "checked"`, `verdict = "confirmed"`, `confirmed_by = "dast"`. Проверка завершена.
    - Если DAST не подтверждает уязвимость → `status` остается `"unchecked"`. Поля `verdict` и `confirmed_by` остаются `null`. Заполняется только карточка `verification_history.dast`.
    
3. Обработка Пентест-средой (Финал):
    
    - Сюда попадают только объекты с `status == "unchecked"`.
    - Если Агент дожимает уязвимость → `status = "checked"`, `verdict = "confirmed"`, `confirmed_by = "pentest-agent"`.
    - Если Агент тоже ломает зубы → `status = "checked"`, `verdict = "unconfirmed"`, `confirmed_by = null`. Проверка принудительно закрывается.
    

(Note: как ясно из контекста, vulnerability может быть обнаружена на любом этапе, теоретически даже на пентесте. Соответственно объект VLS может билднуться на любом этапе. Возможно имеет смысл прямо указать source, хотя не ясно, какой практический смысл оно может нести)
---
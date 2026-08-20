второе название - sandbox-runner

Находится внутри песочницы и занимается мониторингом отдельных контейноров, принятием логов/респонсов ну и вся херня.

# 3. Sandbox Runner / sandboxd
`xD`

`SandboxD располагается внутри sandbox-окружения и является локальным daemon/supervisor.`

Его задача — управление внутренней жизнью sandbox.

## 3.1. Ответственность

Runner:

- жизненный цикл и состояние контейнеров 2-го уровня;
- собирает и агрегирует системные и app-level логи, состояние sandbox;
- контролирует базовые признаки аномального поведения;
- передаёт логи, телеметрию, респонсы;
- сообщает Supervisor об аномалиях.
- предоставляет агенту необходимые системные интерфейсы, данные, настраивает соединение;

Условно(нихуя себе chatgpt "условно" написал. Херня тут соевая написана, можно не читать):
```
sandboxd
│
├── container lifecycle
│   ├── create
│   ├── start
│   ├── stop
│   ├── reset
│   └── destroy
│
├── monitoring
│   ├── process state
│   ├── resource usage
│   ├── exit status
│   └── abnormal behaviour
│
├── logging
│   ├── agent logs
│   ├── target logs
│   ├── system logs
│   └── session logs
│
└── external interface
    └── sandbox-supervisor
```




Примерно сценарий реакции на аномалии описан в [[sandbox supervisor system]]
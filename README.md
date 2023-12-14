### IDS сенсор на GO

## Сборка

Установите необходимые библиотеки:

```bash
libpcap-dev libsystemd-dev libyara-dev
```

Соберите проект:

```bash
go build
```

Запустите программу:

```bash
./go-sensor
```

### Пример использования

```bash
./go-sensor -i en0 -r test_rules.yar -h localhost:9925
```

# onecadmin

`onecadmin` - полноэкранный TUI и набор CLI-команд для администрирования
кластеров 1С:Предприятия через уже запущенный RAS и установленный `rac.exe`.
Интерфейс и сообщения приложения выводятся на русском языке, а команды CLI,
параметры, канонические поля, ключи JSON и колонки CSV остаются английскими.

Подробные требования находятся в [docs/specification.md](docs/specification.md).

## Требования

- Windows 10/11 x64.
- Платформа 1С:Предприятие 8.3.20 или новее.
- Запущенная и доступная служба RAS.
- Один endpoint RAS должен возвращать ровно один кластер.
- Для portable EXE отдельно установленный Python не требуется.
- `rac.exe` не входит в поставку и автоматически ищется среди установленных
  платформ 1С.

Приложение не устанавливает и не запускает `ras.exe`.

## Быстрый старт

Добавление подключения с парольной аутентификацией:

```powershell
onecadmin cluster add `
  --name dev `
  --ras RV-DEV-1C01:1545 `
  --auth password `
  --user cluster_admin `
  --password cluster_password
```

Удаление настроенного подключения:

```powershell
onecadmin cluster remove --name dev
```

Добавление общей учетной записи администратора информационных баз:

```powershell
onecadmin cluster add `
  --name dev `
  --ras RV-DEV-1C01:1545 `
  --auth password `
  --user cluster_admin `
  --password cluster_password `
  --infobase-auth password `
  --infobase-user infobase_admin `
  --infobase-password infobase_password
```

Запуск TUI:

```powershell
onecadmin
```

Поиск баз:

```powershell
onecadmin infobase search zup_corp
onecadmin infobase search 'zup_corp%'
onecadmin infobase search 'zup_corp%' --cluster 'prod%'
```

Поиск сеансов:

```powershell
onecadmin session list --infobase zup_corp
onecadmin session list --query 'DOMAIN\ivanov'
onecadmin session list --query 'PC-%'
onecadmin session list --top 10 --sort cpu_time_total:desc
```

Поиск соединений:

```powershell
onecadmin connection list --infobase 'zup%'
onecadmin connection list --query 'APP-SERVER%'
onecadmin connection list --sort connected_at:desc
```

Завершение сеансов и разрыв соединений:

```powershell
onecadmin session kill --id 00000000-0000-0000-0000-000000000001
onecadmin session kill --user 'test%' --infobase zup_corp --force
onecadmin connection kill --id 00000000-0000-0000-0000-000000000002
```

Без `--force` опасная операция показывает выбранные объекты и запрашивает
подтверждение. Операция без предметного селектора запрещена даже с `--force`;
одного `--cluster` недостаточно.

## Маски и фильтры

Именованные строковые параметры используют SQL LIKE:

- `%` - любое количество символов;
- `_` - ровно один символ;
- `\%` и `\_` - литеральные `%` и `_`.

Без активных wildcard используется точное сравнение без учета регистра.

Универсальный фильтр имеет формат `field:operator:value`:

```powershell
onecadmin session list --filter cpu_time_total:gt:100000
onecadmin session list --filter app_id:like:1CV8%
onecadmin session list `
  --filter cpu_time_total:gt:100000 `
  --filter app_id:like:1CV8%
```

Операторы: `eq`, `ne`, `like`, `gt`, `ge`, `lt`, `le`. Повторенные фильтры
объединяются через AND. Список канонических полей приведен в
[`docs/specification.md`](docs/specification.md); имена RAC нормализованы в
snake_case. Короткий alias `cpu_time` намеренно отсутствует: используйте
`cpu_time_total`, `cpu_time_current` или `cpu_time_last_5min`.

## Форматы вывода

```powershell
onecadmin session list --format table
onecadmin session list --format json
onecadmin session list --format csv
onecadmin session list --columns cluster,infobase,user_name,cpu_time_total
onecadmin session list --columns '*'
```

Таблица форматирует размеры и длительности для чтения человеком. JSON и CSV
сохраняют машинные значения, полные UUID и даты ISO 8601. Данные пишутся в
stdout, диагностика - в stderr.

## Конфигурация

Путь по умолчанию:

```text
%APPDATA%\onecadmin\config.yaml
```

Если выбранного файла нет, приложение создает пустую конфигурацию версии 1.
Другой файл можно выбрать глобальной опцией или переменной окружения:

```powershell
onecadmin --config D:\configs\onecadmin.yaml session list
$env:ONECADMIN_CONFIG = 'D:\configs\onecadmin.yaml'
```

Явный RAC задается через `--rac-path`, `ONECADMIN_RAC_PATH`, настройку
конкретного кластера или глобальный `settings.rac_path`. Затем проверяются
`PATH`, реестр Windows и стандартные каталоги установки 1С. В auto-режиме
версии 8.3.20+ проверяются от новой к старой, а несовместимая версия заменяется
следующим кандидатом.

## Аутентификация

Поддерживаются режимы `password` (имя администратора и пароль передаются в
RAC) и `none` (учетные данные не передаются). Доменная аутентификация текущей
учетной записью Windows не поддерживается: `rac.exe` ее не реализует, поэтому
соответствующих опций в приложении нет.

## TUI

В TUI доступны подключения к кластерам, credential overrides информационных
баз, поиск баз, сеансы, соединения, рабочие процессы и диагностика. Основные
клавиши:

| Клавиша | Действие |
|---|---|
| `Tab`, `Shift+Tab`, `Left`, `Right` | Сменить раздел |
| `1`...`7` | Открыть раздел по номеру |
| `Up`, `Down`, `PgUp`, `PgDn`, `Home`, `End` | Навигация по таблице |
| `Enter` | Показать все известные поля строки |
| `Space` | Отметить сеанс, соединение или рабочий процесс |
| `F5` | Обновить активную вкладку |
| `a` | Включить или выключить автообновление |
| `[` и `]` | Выбрать интервал 5, 10, 30 или 60 секунд |
| `i` | Задать пользовательский интервал |
| `/`, `f`, `s`, `c` | Изменить query, фильтр, сортировку или колонки |
| `g` | Выбрать кластер для фильтрации |
| `n` | Добавить подключение или credential override |
| `Delete`, `x` | Удалить подключение или credential override |
| `k` | Завершить отмеченные объекты после подтверждения |
| `m` | Переключить мышь между управлением TUI и выделением текста |
| `?` | Открыть справку |
| `Esc` | Закрыть окно, отменить задачу или выйти с основного экрана |
| `q`, `Ctrl+C` | Выйти |

В текстовых полях доступны перемещение каретки стрелками, `Backspace`,
`Delete` и очистка через `Ctrl+U`. В поле `auth_mode` клавиши `F2`, `Left` и
`Right` переключают `none`/`password`.

Автообновление по умолчанию выключено. Пользовательский интервал не может быть
меньше двух секунд; новый запрос не запускается поверх незавершенного.

## Безопасность

Пароли по требованиям приложения хранятся в YAML открытым текстом. Это не
шифрование, поэтому конфигурационный файл и учетная запись Windows должны быть
защищены средствами операционной системы.

Пароль, переданный через `--password`, виден в истории PowerShell. RAC также
принимает пароль аргументом, поэтому он может быть кратковременно виден в
списке процессов. Технические логи, диагностические сообщения и JSON-ошибки
маскируют известные приложению секреты.

Технический лог:

```text
%LOCALAPPDATA%\onecadmin\logs\onecadmin.log
```

Лог ротируется при размере 10 MiB; сохраняется пять файлов.

## Коды завершения

| Код | Значение |
|---:|---|
| `0` | Успех, включая пустой результат чтения |
| `1` | Внутренняя ошибка |
| `2` | Ошибка аргументов, конфигурации или запроса |
| `3` | Совместимый `rac.exe` не найден |
| `4` | Ошибка для всех выбранных целей |
| `5` | Частичный успех |
| `6` | Требуется подтверждение или операция отменена |
| `7` | Опасная операция не нашла объектов |
| `130` | Прерывание пользователем |

## Сборка EXE

Установите stable Rust и Visual Studio Build Tools с компонентами C++, затем
выполните:

```powershell
cargo build --release --locked
target\release\onecadmin.exe --version
```

Результат находится в `target\release\onecadmin.exe`. Release-профиль и
`.cargo\config.toml` создают portable EXE со статически связанным CRT.
Системные DLL Windows, компоненты 1С и внешний `rac.exe` в него не включаются.

## Разработка

Минимальная поддерживаемая версия Rust - 1.88. Основные проверки:

```powershell
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets
cargo audit
cargo deny check
cargo llvm-cov --locked --all-features --workspace --all-targets
```

Последние три команды требуют `cargo-audit`, `cargo-deny` и `cargo-llvm-cov`.
GitHub Actions выполняет проверки зависимостей и покрытия при каждом push и
pull request вместе со сборками stable и Rust 1.88 под Windows.

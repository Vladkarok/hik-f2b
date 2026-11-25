# Glossary / Глосарій

The documentation uses one term for one thing. Where hik-f2b prints a word
for a concept (log lines, `--check`, `--help`, config keys), the
documentation uses the same word.

Документація вживає один термін для одного поняття. Якщо hik-f2b сам друкує
слово для поняття (рядки журналу, `--check`, `--help`, ключі конфігу),
документація вживає те саме слово.

| English | Українська | Meaning | Значення | Do not use / Не вживати |
| --- | --- | --- | --- | --- |
| NVR | реєстратор | The Hikvision recorder whose log hik-f2b reads. | Реєстратор Hikvision, журнал якого читає hik-f2b. | recorder, DVR (except in Requirements); відеореєстратор (лише у вступі), NVR у тексті |
| device | пристрій | Any piece of hardware: an NVR or the router. | Будь-яке обладнання: реєстратор або роутер. | "device" for the NVR alone; «пристрій» лише про реєстратор |
| router | роутер | The MikroTik router that bans addresses. | Роутер MikroTik, на якому діють бани. | маршрутизатор |
| host | хост | The Linux machine that runs hik-f2b. | Linux-машина, на якій працює hik-f2b. | server, machine; сервер |
| address | адреса | The source IPv4 address of a failed login. | IPv4-адреса джерела невдалого входу. | IP (in prose); IP, айпі (у тексті) |
| own address | власна адреса | An IPv4 address of the router or an NVR of the config, or the host's address toward one of them. hik-f2b finds them at run time and never bans them. | IPv4-адреса роутера чи реєстратора з конфігу або адреса хоста в бік одного з них. hik-f2b знаходить їх під час роботи й ніколи не банить. | self address, host address (for the whole set); своя адреса, адреса хоста (про весь набір) |
| failed login | невдалий вхід | One login to an NVR with a wrong password or user name. | Один вхід на реєстратор із неправильним паролем чи іменем. | failure, failed attempt; невдала спроба, помилка входу |
| log entry | запис журналу | One record in the NVR log. | Один запис у журналі реєстратора. | event, line; подія |
| NVR log | журнал реєстратора | The log that the NVR keeps and hik-f2b reads. | Журнал, який веде реєстратор і читає hik-f2b. | лог |
| hik-f2b log | журнал hik-f2b | The lines hik-f2b writes (`journalctl`). | Рядки, які пише hik-f2b (`journalctl`). | output (for the log); лог |
| user name | ім'я користувача | The name typed at a login. | Ім'я, введене під час входу. | login name, username; логін, ім'я для входу |
| client app | клієнтський застосунок | An app that connects to the NVR, such as iVMS-4200. | Застосунок, що підключається до реєстратора, наприклад iVMS-4200. | client, program; програма, клієнт |
| poll | опитування | One read of every NVR log, every `poll_interval`. | Одне читання журналу кожного реєстратора, раз на `poll_interval`. | cycle (`--help` says "poll cycle"); цикл |
| ban | бан, банити | hik-f2b adds an address to the address-list. | hik-f2b додає адресу до address-list. | block (for this action); блокувати (про цю дію) |
| block | блокувати | The router drops the traffic of a banned address. | Роутер відкидає трафік забаненої адреси. | cut off, shut out; відрізати |
| timed ban | тимчасовий бан | A ban with a timeout of `bantime`. | Бан із таймаутом `bantime`. | temporary ban; бан на час |
| permanent ban | постійний бан | A ban without a timeout (`bantime = permanent`). | Бан без таймауту (`bantime = permanent`). | static ban; вічний бан |
| remove a ban | зняти бан | Delete the address-list entry on the router. | Видалити запис з address-list на роутері. | lift a ban, unban; розбанити |
| address-list | address-list | The RouterOS list that holds banned addresses (`cctv_ban`). | Список RouterOS, у якому лежать забанені адреси (`cctv_ban`). | ban list, block list; бан-лист, чорний список |
| address-list entry | запис в address-list | One address in the address-list, with or without a timeout. | Одна адреса в address-list, з таймаутом чи без. | ban entry |
| drop rule | правило відкидання | The firewall rule that blocks addresses from the address-list. | Правило фаєрвола, яке блокує адреси з address-list. | block rule, ban rule; правило блокування |
| config | конфіг | The file `hik-f2b.ini`. | Файл `hik-f2b.ini`. | configuration file, settings file; файл налаштувань, конфігурація (про файл) |
| setting | параметр | One `key = value` line in the config. | Один рядок `ключ = значення` у конфігу. | option (for this); опція (про це) |
| option | опція | A command-line option such as `--check`. | Опція командного рядка, наприклад `--check`. | flag, switch, setting; ключ, параметр (про це) |
| secret | секрет | A password or token. | Пароль або токен. | credential (for one password or token; "credentials" means user name and password) |
| secret file | файл секрету | A file with one secret, named by a `*_file` setting. | Файл з одним секретом, на який вказує параметр `*_file`. | password file; файл пароля |
| service | сервіс | hik-f2b while it runs under systemd. | hik-f2b, коли він працює під systemd. | daemon; демон, служба |
| Quadlet unit / systemd unit | юніт Quadlet / systemd-юніт | `deploy/hik-f2b.container` / `deploy/hik-f2b.service`. | `deploy/hik-f2b.container` / `deploy/hik-f2b.service`. | unit file (for the service itself) |
| image / container | образ / контейнер | The published container image / a running copy of it. | Опублікований образ контейнера / його запущений екземпляр. | package (except the GitHub package page) |
| dry run | пробний режим | `dry_run = true`: hik-f2b logs bans but applies none. | `dry_run = true`: hik-f2b пише бани в журнал, але не застосовує. | test mode; тестовий режим |
| notify-only mode | режим лише сповіщень | No `[mikrotik]` section: hik-f2b reports addresses and bans nothing. | Без секції `[mikrotik]`: hik-f2b повідомляє про адреси й нічого не банить. | report-only mode |
| notification | сповіщення | A Telegram message about a ban or detection. | Повідомлення в Telegram про бан чи виявлену адресу. | alert (for this) |
| health alert | сповіщення про стан | A message that hik-f2b cannot do its job. | Повідомлення, що hik-f2b не може виконувати свою роботу. | failure alert; сповіщення про збій, алерт |
| country database | база країн | The `.mmdb` file named by `country_db`. | Файл `.mmdb`, на який вказує `country_db`. | GeoIP database; геобаза |
| topic | тема | A Telegram forum topic (`message_thread_id`). | Тема форуму в Telegram (`message_thread_id`). | thread; гілка, тред |

## Writing rules / Правила написання

For steps and other "do this" text:

- One action per sentence. Start with the verb, unless a condition or a
  purpose comes first ("If …", "To …").
- At most 20 words in an instruction sentence.
- Put a condition before its action, and a warning before its step.
- Write the expected result as its own sentence after the step.
- Use active voice and simple tenses. No idioms, no contractions, no
  "simply", "just" or "easily".
- Number the steps when order matters. Use bullets when it does not.
- Use the terms from the table above.
- Do not change fenced code blocks, command output or config examples.

Для кроків та інших інструкцій:

- Одна дія в реченні. Речення починається з дієслова у формі «ви»
  (виконайте, відкрийте), якщо перед ним немає умови чи мети («Якщо …»,
  «Щоб …»).
- Не більше 20 слів у реченні з інструкцією.
- Умова стоїть перед дією, попередження — перед кроком.
- Очікуваний результат — окреме речення після кроку.
- У кроках — лише активні конструкції: без «було виконано», без форм на
  «-но/-то» і без ланцюжків дієприслівників. Без канцеляризмів і кальок.
- Кроки нумеруйте, якщо важливий порядок; інакше — маркований список.
- Уживайте терміни з таблиці вище.
- Не змінюйте блоки коду, вивід команд і приклади конфігу.

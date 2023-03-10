### Общее описание

Программа scan2ban предназначена для выявления и блокировки адресов, трафик с которых имеет признаки сканирования. В текущей реализации к таком признакам относится:

* обращение на порт из списка
* число обращений к любым портам с превышением порогового значения

### Общая логика

В конец цепочки INPUT ставится фиксация в журнал всех пакетов не отработаных раннее. Сценарий построчно разбирает записи с тегом [S2BLOG] следующим образом:

- Проверят адрес источника в базе и если он там отсутствует вносит его в таблицу ips с фиксацией в колонке last времени жизни записи расчитываемой как текущее время + config/blocktime и выводя сообщение `[NOTICE]: Новый адрес: `
- Немедленно блокирует источник если порт назначения есть в списке config/instant_ports, выводя сообщение `[NOTICE]: Блокируем по instant_port:`
- Если адрес уже присутствует в таблице, проверяет, что порт назначения отсутствует в списке config/ignore_ports и если порта там нет - увеличивает колонку count для него и в случае, если счетчик запросов превысил config/blockcnt - блокирует адрес с сообщением `Блокируем по instant_port`

Блокировка осуществляется внесением записи в цепочку s2bdrop, которая перенаправляет пакет в цепочку s2bdroplog в которой фиксируется факт отброшенного пакета (теги [DROP][S2BLOG])

Раз в config/cleanperiod все заблокированные адреса проверяются на факт истечения времени жизни. Если время истекло запись удаляется. 
Раз в config/syncperiod производится проверка появления в базе правил не существующих на текущей установке. Если такие записи есть, они добавляются в правило с сообщением: `Блокируем по бд:`. Если локальное правило отсутствует в бд, правило удаляется с сообщением: `Удаляем блокировку по бд`

### Реализация

Создаются цепочки iptables:
- s2bblock: заблокированные адреса
- s2bdroplog: финишная цепочка, фиксирующая блокировку с тегом [DROP][S2BLOG]
- s2blog: цепочка фиксирующая пакеты не обработанные штатными правила с тегом [S2BLOG[

В начало цепочки INPUT добавляется редирект на s2bblock
В конце INPUT редирект на s2blog

Цепочка s2blog заполняется правила для игноируемых сетей и портов, попадание в которое вызывает возврат в INPUT. Если пакет дошел до конца s2blog, он будет зафиксирован.

Цепляется в бд. Если ее нет (sqlite3) или нет таблиц (postgres), создаем структуру.
Если база есть, из таблицы ip выгружаются поля ip для которых поле block == 1 - добавляется в цепочку s2bdrop с редиректом на s2bdroplog

Запускается процесс мониторинга сообщений iptables (config/moncmd, может быть как journalctl так и dmesg -W). Фильтрация по макеру [S2BLOG] Сообщения укладываются в очередь. 

В основном цикле программы раз в секунду проверяются сообщения и очереди. Если есть новые, строка разбирается в соответствии с логикой. Если такой адрес ранее уже был (в наличии в таблице ips), то его счетчик увеличивается. Если у строки нет тега [DROP] (т.е. он не заблокирован) проверяется, что счетчик выше порога. Если да, то адрес вносится в цепочку s2bdrop, а записи в таблице ip поле drop = 1.

При выходе, все цепочки iptables очищаются и удаляются.

### Структура пакета

- config.yml: конфигурационный файл
- scan2ban.py: основной сценарий
- sqlite база
  - ips: адрес, счетчик пакетов, флаг блокировки [0|1], временем последнего события
  - details: таблица событий. source/dest/dport/time
  - адреса хранятся как int, время - секунды (epoch time)
- export.py: выгрузка таблицы состояния адресов

### Установка

Проверялась на ubuntu/20 и debian/10

apt install  python3-yaml 

Рекомендуется добавить в цепочку INPUT правила ACCEPT для рабочих портов. Любой трафик дошедший до конца цепочки INPUT обработан в соответствии с общей логикой, что, например, при отстствии ACCEPT на `-tcp --dport 22` заблокирует в т.ч. уже открытую ssh сессию.

скопировать конфиг: `cp config.yml.example config.yml` и если надо отредактировать 
### База данных

По умолчанию используется sqlite3. 

#### Работа с sqlite (локальный режим)

В config.yml раскоментировать секцию sqlite3. БД будет создана при старте автоматически.

#### Работа с общей БД (распределенный режим)

В случае обединения нескольких машин в группу, можно использовать общую базу данных которая будет использоватья одновременно всеми настроеными агентами. Следует учитывать, что список блокировок и счетчиков так-же будет единым.

Установить сервер (или только клиент, если база внешняя), а так-же пакет `python3-psycopg2`

На сервере создать базу и пользователя для нее:

sudo -u postgres psql
postgres=# create database s2b;
postgres=# create user s2buser with encrypted password 'mypass';
postgres=# grant all privileges on database s2b to s2buser;

Проверить, что доступ есть `# psql -d s2b -h x.x.x.x -U s2buser -W`

Раскоментировать секцию в конфиге подставив нужные параметры, закоментировать секцию sqlite3.

Для получения читаемой выборки по адресам, можно использовать следующую конструкцию: `select '0.0.0.0'::inet + cast(ip as bigint),count,block from ips;` либо утилиту export.py

### Запуск

python3 scan2ban.py -f

### Запуск службы

Скопировать scan2ban.service в /etc/systemd/system
Поправить пути до каталога с программой
systemctl daemon-reload
systemctl start scan2ban

Для наблюдения за выводом можно использовать `journalctl -ef scan2ban`

### Работа в контейнере

В контейнерах не функционирует механизм `-j LOG`, потому применяется `-j NFLOG`. Переключение осуществляется параметром `config/fwlogmode`. Предварительно необходимо установить и настроить пакет ulogd2 создав конфигурационный файл /etc/ulogd2.conf например:

```
[global]

# logfile for status messages
logfile="syslog"

# loglevel: debug(1), info(3), notice(5), error(7) or fatal(8) (default 5)
loglevel=3

# stack for NFLOG to syslog forward
stack=log1:NFLOG,base1:BASE,ifi1:IFINDEX,ip2str1:IP2STR,print1:PRINTPKT,sys1:SYSLOG

[sys1]
facility=LOG_DAEMON
level=LOG_DEBUG
```

После чего перегрузить приложение `systemc restart ulogd2`, запустить `scan2ban.py` и убедиться, что в `journalctl -f` появляются записи от правил.

### TODO

* поддержка других языков
* автозаполнение игнорируемых портов
* автодетект адреса управляющего терминала во избежании непреднамеренной блокировки (last -ia)
* выгрузка данных из таблицы details
* защита от флуда

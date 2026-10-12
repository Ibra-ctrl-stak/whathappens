# Fixture: github.com/robots.txt

**Ключи одной публичной сессии — безопасно, не для продакшена.**

`session.json` — одна реальная запись `GET https://github.com/robots.txt` (TLS 1.3),
включая её keylog (`CLIENT_/SERVER_*_TRAFFIC_SECRET`). Эти ключи эфемерны и
открывают только эту сессию, содержимое которой и так публично. Так же устроены
тестовые захваты Wireshark и другие TLS-тестсьюты. Там же есть анонимная cookie
`_gh_sess` (`logged_in=no`), которую GitHub выдал скрипту: к аккаунтам не
относится. Не копируйте сюда записи с вашими собственными логинами или cookie.

Живые записи (`out/`: захваты, keylog, session.json) в git не попадают.

## Откуда значения

- `session.json` — запись `day1.mjs` (формат 2). Её байты совпали с захватом
  Wireshark на интерфейсе туннеля: DNS-запросы и ответы, оба TCP-потока,
  расшифровка Wireshark по этому keylog (`compare-wireshark.mjs`, 12/12).
- `expected.json` — то, что увидел tshark 4.6.9 в том же захвате
  (`tools/extract-expected.mjs`). Независимый оракул: наш код его не порождает.

## Перезапись

1. Захват на интерфейсе, через который идёт трафик (dumpcap/Wireshark), во время `node day1.mjs`.
2. `node compare-wireshark.mjs` — должно быть `STEP 4: MATCH`.
3. Скопировать `out/session.json` сюда и пересоздать оракул:
   `node tools/extract-expected.mjs out/capture.pcapng out/session.json out/keylog.txt > test/fixtures/github-robots/expected.json`

## capture.pcapng / expected-capture.json

`capture.pcapng` — пакеты **только этого соединения** (34 кадра) из захвата, сделанного во время
записи на интерфейсе VPN-туннеля. Вырезано `tools/trim-pcapng.mjs`: новый файл с одной секцией без
опций (нет сведений об ОС, устройстве, приложении), один интерфейс (raw IP, наносекунды), без
комментариев. Посторонних пакетов нет (проверено tshark: одно TCP-соединение). Исходный захват в
git не входит. `expected-capture.json` — поля каждого кадра по tshark
(`tools/extract-capture-expected.mjs`), независимый оракул для разбора pcapng/TCP.

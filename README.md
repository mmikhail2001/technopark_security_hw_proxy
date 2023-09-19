# technopark_security_hw_proxy

## Запуск прокси-сервера и web api на хосте

- переименовать `docker-compose-mongo.yml` в `docker-compose.yml`
- `docker compose up` -- запуск mongodb (слушает порт 27017)
- `make -B build` -- сборка прокси-сервера и web api, исполняемые файлы сохраняются в папку build
- `./build/proxy/out` -- запуск прокси-сервера (слушает порт 8080)
- `./build/webapi/out` -- запуск web-api (слушает порт 8000)

## Запуск прокси-сервера и web api в докере

- `docker compose up` -- сборка и запуск трех контейнеров: proxy, webapi, mongo. Контейнеры слушают порты 8080, 8000 и 27017 соответственно. 

## Установка сертификатов (Ubuntu)

- `sudo cp .mitm/ca-cert.pem /usr/local/share/ca-certificates/ca-cert.crt` -- копирование сертификата в список доверенных
- `sudo update-ca-certificates` -- обновление доверенных сертификатов

## Использование

- `curl -x 127.0.0.1:8080 -v http://example.com`
- `curl -x 127.0.0.1:8080 -v https://mail.ru`
- web-api 127.0.0.1:8000 имеет **ручки**: `/requests, /requests/{id}, /repeat/{id}, /scan/{id}` 
- использование в браузере **firefox**: указать адрес прокси (настройки -> прокси), импортировать сертификат (настройки -> сертикаты -> импорт ca-cert.pem). Браузер работает в штатном режиме, любые запросы имеют успех, включая login, logout.
- Вход в сервис Google Аккаунт. Интерфейс MongoDB Compass.
- ![image](https://github.com/mmikhail2001/technopark_security_hw_proxy/assets/71098937/2b08b213-7b85-49c4-8421-d0daacef9af5)



## Использование web-api
 
![image|300](https://github.com/mmikhail2001/technopark_security_hw_proxy/assets/71098937/aa32906d-f5ae-49bf-8950-15b419bca8b1)

## Пример уязвимого сервера 
- `vulnerable-test-server/main.go` -- уязвимый сервер, написанный на golang. Отправляет в теле ответа get-параметры без валидации.
- `curl -x 127.0.0.1:8080 -v http://212.233.91.39/?name=mikhail` -- запрос на уязвимый сервер через прокси
- `request.get_params.name = mikhail` и `response.text_body = Hello, mikhail!`
- ![image|300](https://github.com/mmikhail2001/technopark_security_hw_proxy/assets/71098937/4cb9a3b0-bb48-4518-8435-f091b61963ea)
- найдена уязвимость в get-параметре name
- ![image|300](https://github.com/mmikhail2001/technopark_security_hw_proxy/assets/71098937/4038fc77-d78a-4c3e-a8e4-3a8e9245b1d7)

## Замечания
- Замечания по работе web-api и прокси сервера
	- Для сохранения данных запроса и ответа используется NoSQL база данных **mongodb**
	- Удаляется заголовок `Accept-Encoding` для отсутствия сжатия. В ответ от целевого сервера добавляется заголовок `Content-Encoding: identity`
	- В ответ от целевого сервера добавляется заголовок `X-Transaction-Id: {id}`, содержащий id http транзакции, данные по которой сохранились в БД по _id = {id}
	- Парсинг тела POST запроса происходит в том случае, если клиент выставил заголовок `Content-Type: application/x-www-form-urlencoded`
	- Тело ответа сохраняется в БД в бинарном формате. В текстовом формате сохраняется в том случае, если целевой сервер выставил заголовок `Content-Type`, содержащий в значении `text` или `application` (исключение: `application/octet-stream`). Данное решение требует пересмотра.
- Трудности разработки
	- Не удается проэксплуатировать уязвииый веб-сервер при запуске последнего на хосте (`curl -x 127.0.0.1:8080 127.0.0.1/?name=mikhail`). Ошибка ` reverseproxy.go:666: http: proxy error: dial tcp 127.0.0.1:80: connect: connection refused`
	- Изначальная реализация предполагала запуск ubuntu контейнеров с приаттаченной директорией с бинарными файлами, которые билдились на хосте. При таком подходе curl выдавал ошибку `curl: (35) error:0A000438:SSL routines::tlsv1 alert internal error`. Далее была предпринята успешная попытка использовать golang контейнеры и билдить код непосредственно в них. 
- Перспективы развития: в первую очередь, устранить следующие проблемы.
	- username и password от БД необходимо передавать через переменные окружения (файл `.env`).
	- Конфигурацию (например, url адреса) нужно хранить в файлах, а не "хардкодить" в константах.
	- Докерфайлы создают image, копируя всю директорию, а не соответствующий сервер
	- Отсутствие рефакторинга и ревью.

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
- web-api 127.0.0.1:8000 имеет ручки: `/requests, /requests/{id}, /repeat/{id}, /scan/{id}` 
- использование в браузере firefox: указать адрес прокси (настройки -> прокси), импортировать сертификат (настройки -> сертикаты -> импорт ca-cert.pem)

## Использование web-api
 
![image](https://github.com/mmikhail2001/technopark_security_hw_proxy/assets/71098937/aa32906d-f5ae-49bf-8950-15b419bca8b1)

## Пример уязвимого сервера 
- `vulnerable-test-server` -- уязвимый сервер, написанный на golang. Отправляет в теле ответа get-параметры без валидации.
  

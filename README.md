Утилита для быстрого поиска дублирующихся по подержимому файлов.

Проект был создан в MS Visual Studio Community 2022
Сам git репозитарий хранит в себе все чтобы открыть проект в MS Visual Studio Community.
После открытия проекта необходимо указать путь библиотеки Boost, а точнее:
- Проект 
-  - Свойства
-  -  - С/С++
-  -  -  - Общие
-  -  -  - Дополнительные каталоги включаемых файлов
         - C:\boost_1_88_0
-  -  - Компоновщик
-  -  -  - Дополнительные каталоги библиотек
         - C:\boost_1_88_0\stage\lib
         - C:\boost_1_88_0\libs

В папке x64/Debyg имеется собранный бинарник готовый к работе.
Вызов возможен через командную строку или bat файл.
Пример вызова из командной строки:
bayan --scan-dir C:\Users\Russell\Desktop\OTUS
Производится сканирование указанной директории на наличие одинаковых по содержанию файлов.

Также имеются дополнительные опции:
- --help (вывод информации о применяемых командах)
- --scan-dir directory (поиск одинаковых по содержанию файлов)
- --exclude-dir directory (добавление исключения для определенных папок, которые не будут просмотрены)
- --level (уровень по умолчанию 0 - только указанная директория без учета вложенных папок, 1 - все папки в данной диреткории)
- --min-size (минимальный размер файла для сканирования)
- --mask (фрагмент названия файла без учета регистра - поиск и сканирование только по названию)
- --block-size (размер блока, которым производится чтения файлов - по умолчанию 1024)
- --hash-algorithm (алгоритм хэширования - по умолчанию crc32)

# Установка CLIPS 6.4.2 на macOS

Эта инструкция применима для **macOS**.

Ссылка на скачивание CLIPS 6.4.2:
[https://sourceforge.net/projects/clipsrules/files/CLIPS/6.4.2/](https://sourceforge.net/projects/clipsrules/files/CLIPS/6.4.2/)

## Как устанавливали

1. Скачали исходники:
```bash
curl -L -o /tmp/clips_core_source_642.tar.gz "https://sourceforge.net/projects/clipsrules/files/CLIPS/6.4.2/clips_core_source_642.tar.gz/download"
```

2. Распаковали архив:
```bash
tar -xzf /tmp/clips_core_source_642.tar.gz -C /tmp
```

3. Собрали релизный бинарник:
```bash
make -C /tmp/clips_core_source_642/core release
```

4. Перенесли бинарник в постоянное место (чтобы не терялся при очистке `/tmp`):
```bash
mkdir -p ~/.local/bin
cp /tmp/clips_core_source_642/core/clips ~/.local/bin/clips
chmod +x ~/.local/bin/clips
```

5. Проверили, что `~/.local/bin` есть в `PATH`:
```bash
echo "$PATH"
```
Если `~/.local/bin` отсутствует, добавить в `~/.zshrc`:
```bash
export PATH="$HOME/.local/bin:$PATH"
```
После этого выполнить:
```bash
source ~/.zshrc
```

## Как проверить, что CLIPS работает

1. Убедиться, что команда находится в `PATH`:
```bash
command -v clips
```
Ожидаемо: путь вида `/Users/<user>/.local/bin/clips`.

2. Проверить запуск интерпретатора:
```bash
printf "(exit)\n" | clips
```
Ожидаемо в выводе есть строка версии, например:
`CLIPS (6.4.2 1/14/25)`.

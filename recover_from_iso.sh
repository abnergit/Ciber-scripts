#!/bin/bash

# Verificar se o Sleuthkit está instalado
if ! command -v fls > /dev/null; then
  echo "O Sleuthkit não está instalado. Por favor, instale-o antes de continuar."
  exit 1
fi

# Definir o local do sistema de arquivos a ser analisado
fs_location="pendrive.iso"

# Definir o local de destino para os arquivos recuperados
mkdir fls_recover
destination_folder="fls_recover/"

# Recuperar arquivos com o comando fls
fls -r $fs_location | while read line; do
  inode=$(echo $line | cut -d':' -f1 | rev | cut -d' ' -f1 | rev)
  file_name=$(echo $line | rev | awk '{print $1}' | rev)
  icat $fs_location $inode > "$destination_folder/$file_name"
done

echo "Arquivos recuperados com sucesso!"

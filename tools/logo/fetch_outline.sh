#!/bin/bash

# defaults
WIDTH="40"
IMAGE="sith.png"
INVERT=0
CONTRAST=0
EXTRA_PROCESS='s/<[^>]+>//g; s/[^ ]/0/g; /^ *$/b;'
EXTRA_ARGS=()
TYPE="ascii"
BROWSER="ie" # only used for HTML

while [[ $# -gt 0 ]] ; do
  case $1 in
    -w)
      WIDTH="$2"
      shift
      ;;
    -w*)
      WIDTH="${1#-w}"
      ;;
    -i)
      IMAGE="$2"
      shift
      ;;
    -i*)
      IMAGE="${1#-i}"
      ;;
    -o)
      OUTFILE="$2"
      shift
      ;;
    -o*)
      OUTFILE="${1#-o}"
      ;;
    -b)
      BROWSER="$2"
      shift
      ;;
    -b*)
      BROWSER="${1#-b}"
      ;;
    -I)
      INVERT=1
      ;;
    -C)
      CONTRAST=1
      ;;
    -h)
      TYPE="html"
      EXTRA_PROCESS=''
      EXTRA_ARGS=(
      -F 'characters=0'
      -F 'grayscale=2'
      )
      ;;
  esac
  shift
done
[[ "${WIDTH}" =~ ^[0-9]+$ && "${BROWSER}" =~ ^[a-zA-Z]+$ ]] || exit 1
[[ -z ${OUTFILE} ]] &&
  OUTFILE="out/logo_outline_W${WIDTH}_B${BROWSER}_I${INVERT}_C${CONTRAST}.${TYPE/ascii/txt}"

if [[ "${OSTYPE}" == "linux-gnu" ]]; then
  SED='sed -r'
else
  SED='gsed -E'
fi

curl -s -F 'image=@'"${IMAGE}"';type=image/png' \
  -F "width=${WIDTH}" \
  -F 'bgcolor=WHITE' \
  -F 'textcolor=BLACK' \
  -F "contrast=${CONTRAST}" \
  -F "invert=${INVERT}" \
  -F "browser=${BROWSER}" \
  "${EXTRA_ARGS[@]}" \
  https://www.text-image.com/convert/pic2${TYPE}.cgi \
    | ${SED} -n '/<!-- IMAGE BEGINS HERE -->/,/<!-- IMAGE ENDS HERE -->/{'"${EXTRA_PROCESS}"'p}' \
    > "${OUTFILE}"

n=$(tr -d '\n ' < "${OUTFILE}" | wc -m | tr -d '\n ')
echo "Saved to ${OUTFILE}."
if [[ "${TYPE}" == "ascii" ]] ; then
  echo "Saved to ${OUTFILE}. There are ${n} characters in the outline:"
  cat "${OUTFILE}"
fi

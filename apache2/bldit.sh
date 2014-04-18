if test $# -ne 1; then
  echo "Usage: $0 {24-64|25-64|...}" 1>&2
  exit 1
fi

~/inst/${1}/bin/apxs -ci -Wl,-lcrypto mod_qos.c

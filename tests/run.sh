#!/bin/sh
# bw-vault の試験一式（偽の agent・偽の API・偽の polkit を使うので、sudo も実際の保管庫も要らない）。全部通れば終了コード 0
cd "$(dirname "$0")" || exit 1
rc=0
for t in test_gate.py test_bwv.py test_pinentry.py test_setup.py; do
  echo "== $t"
  out=$(python3 -B "$t" 2>&1); code=$?
  echo "$out" | grep -E "^(NG|結果|漏れた)"
  [ "$code" -eq 0 ] || rc=1
done
exit $rc

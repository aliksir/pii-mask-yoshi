// 自動生成ファイル — 手動編集禁止
// 生成コマンド: node scripts/encode-js-patterns.mjs
// XOR + base64 で難読化された PII 検出パターン定義
// 目的: grep/静的解析での平文パターン検出を防止（暗号学的保護ではない）

export const XOR_KEY = 'E8jJuagGmAv9mFnqKuTCV8Kr6GW/qIQWVvFMmEBvwNM=';

export const BUILTIN = [
  {
    "id": "email",
    "category": "pii",
    "regex": "SKnkw+krwjvQoXe1D8/vCunrswSS0sU7DMFhoW5CnfhP5pLYhXzZJqfFItgGmQ==",
    "maskPrefix": "EMAIL"
  },
  {
    "id": "phone-jp",
    "category": "pii",
    "regex": "I5StwpkqrHbQxD2RG8j2Ku/3jB6L1Q==",
    "maskPrefix": "TEL"
  },
  {
    "id": "ipv4",
    "category": "network",
    "regex": "O/fz5cx9qSfO5QXEA5/xKp7Pk1STm/k=",
    "maskPrefix": "IPv4"
  },
  {
    "id": "ipv6",
    "category": "network",
    "regex": "O/fz4ukr3mrQ/mnHE7m5Zu6flV+W07Y6YYwX2W0pof51+OSA9X2pJ8nl",
    "maskPrefix": "IPv6"
  },
  {
    "id": "local-path-home",
    "category": "pii",
    "regex": "SInk48kr4lbHwwW2BbmXJKfZmz7j9KtLDa8Q62JIoP86leI=",
    "maskPrefix": "PATH"
  }
];

export const EXTRA = [
  {
    "id": "jwt-token",
    "category": "credential",
    "regex": "drGD4ukrwmrQ4mnHE7vvCrma2EnC9KpNF9wW+W0V8P4ql+Tk0zeoJ4DEd9Vxpe8No4aSVZKR2zsL2w==",
    "maskPrefix": "JWT"
  },
  {
    "id": "api-key-openai",
    "category": "credential",
    "regex": "YKPk4skr4krQwmnHE7m5ZfKHlQ==",
    "maskPrefix": "APIKEY"
  },
  {
    "id": "api-key-github",
    "category": "credential",
    "regex": "dKC55vNntXG8tQPaB92fLPGdxBg=",
    "maskPrefix": "APIKEY"
  },
  {
    "id": "api-key-aws",
    "category": "credential",
    "regex": "UoOA+PNHtVHNtWC3UdX0Kg==",
    "maskPrefix": "APIKEY"
  },
  {
    "id": "api-key-anthropic",
    "category": "credential",
    "regex": "YKPk2MZytVCctSOrB77yevuGtR6NmKhr",
    "maskPrefix": "APIKEY"
  },
  {
    "id": "aws-secret-key",
    "category": "credential",
    "regex": "O/fzkZc8+XyOsWa1FZenNLDOnDqAgLssN5Iv/TMc6exM96Lc0XrLbp7qPJ5rh6EysdijAMbU13M1gynsaTOz+Ujy9OT0dbJQvLUDiwee8nr7hMNY4tOwJis=",
    "maskPrefix": "SECRET"
  },
  {
    "id": "azure-account-key",
    "category": "credential",
    "regex": "Uquq1t1o7ECY4WSxa8mYNu/R2EiGh68rC4p+qGwS",
    "maskPrefix": "SECRET"
  },
  {
    "id": "password-kv-slash",
    "category": "credential",
    "regex": "O/fzXganf5t7cNlvVrigNqbGgQvjyvhKNIMj9zQzoq9PqrzKzXTEadTEKsAFuLF9mfW0FpOT+UoK1m7EHTK74j/5+4HV",
    "maskPrefix": "PASSWD"
  },
  {
    "id": "password-kv-en",
    "category": "credential",
    "regex": "T6rhhpJ2+XiO7zaYTpiyNrHYnwHD2+F1JJQ45DQAq7Z94ZXKgl2iNqDEKsBxup4k7pCVOeOPpkoLrDepbF7y624=",
    "maskPrefix": "PASSWD"
  },
  {
    "id": "password-kv-ja",
    "category": "credential",
    "regex": "O/fzWiuXe4lEe9pFyWd+tEEilIY8OWeU742pN8aIYFJvL24hTake4nAtcLZZzplt/0RU/+L09zwNrxDrbFS9j0/v6+X1W+M60alr0lc=",
    "maskPrefix": "PASSWD"
  },
  {
    "id": "connstr-url",
    "category": "credential",
    "regex": "O/fz1NF16WeB6DaZXoOwMrHahBnPx/diMYMp6zwCr710p63b1Gv3ZZr3PYh2z7EltNeaANvB92oklCjxMxy8sn65ucXJa+l7juQ0mVmVriuvypoM3szmP2zeY8MeM7PvLe/r5YFaxVbW",
    "maskPrefix": "CONNSTR"
  },
  {
    "id": "auth-basic",
    "category": "credential",
    "regex": "Ur290cd08XGc7DCFRN6eJOjpiRbWy9hlfaoNtRoO7akj5fCShzvFcMW0JA==",
    "maskPrefix": "SECRET",
    "flags": "i"
  },
  {
    "id": "pem-private-key-block",
    "category": "credential",
    "regex": "PuXklIVE3Uy01gWZAcz9bZD4qTnMg/hTFa0/szwrk5JPu+LF51bdRa7LEbZZz74SjOi6PO/8wVIKgmexfz+SmkWJnfz0dbNAuMF0xwfJ7wye2LQ24oK7O3vcYbUFIYSPYOPhhpJUy0qh63KWb6eeJOnXrDb+9Pc9Kr4c3Q48k5tPu+LF7UjbWaTIDa9uuLF865S4N/b+xUITrT+zCyqZ/j7l5JQ=",
    "maskPrefix": "SECRET"
  },
  {
    "id": "connstr-password",
    "category": "credential",
    "regex": "O/fz6cl163yS6j2WepOmfp7Ywljj265NCMoQ62Iy6w==",
    "maskPrefix": "PASSWD"
  },
  {
    "id": "session-cookie",
    "category": "credential",
    "regex": "QK29lOtp92CU/WO2Wc7qaPjYjRbMwet4Da5hxX8GpK9Zm4zq+0/XRbTcJbpitJESkfihIcPL63g4lC/sHEGzune0lsrNdetikvYlmUOA6wuxgdU5zILfSG2tP8Vr",
    "maskPrefix": "SECRET",
    "flags": "i"
  },
  {
    "id": "ssh-pubkey",
    "category": "credential",
    "regex": "YLuhlIA5onmO+SWPTtb3YvOSlADczPd3KpU/+Wkzs/hSiYj480e1UZy1I9oH3el4n9DaVZPV3ysLiny0cxLo7CmUupLzWMR4oLNw1Q==",
    "maskPrefix": "SECRET"
  },
  {
    "id": "webhook-slack",
    "category": "credential",
    "regex": "e7y9yds8tySV9zaBWbjsJK7Kiw7jhud5O94//TIZqbB2u+bi6SvCatDiaccTy598",
    "maskPrefix": "SECRET"
  },
  {
    "id": "env-credential",
    "category": "credential",
    "regex": "SInk4/Vd2SanqHTTdbnof/2RtzX++9dBGaMI5B8/gYBAn43F91XdSK/dDZZ1sI0ch+WUOu/6zUAXpQnHCyqZr0yJivrtVctUtt0AlnW3hxSQ7rw69O3dagmyHt0EKo6HWomF6tRZ2V6p0Aa+Za+HGb70vyD94MtZHa4ZygwTn4RWioH2502xV46yZLZZzupo+ImzO5306kt80zC/GzHnj32V457UXcZXjrRiyXfP6w==",
    "maskPrefix": "PASSWD"
  },
  {
    "id": "auth-bearer",
    "category": "credential",
    "regex": "Ur290cd08XGc7DCFRN6eJOjpjQTNzfZKJdpkp2EKuZk6k4iU8me1cc21YMR1mul4/4a1Ho2YqGs=",
    "maskPrefix": "SECRET",
    "flags": "i"
  },
  {
    "id": "api-key-google",
    "category": "credential",
    "regex": "UoGz2Pt/w0rQwjjHUNTvbp2GtR6Mm/k=",
    "maskPrefix": "APIKEY"
  },
  {
    "id": "api-key-stripe",
    "category": "credential",
    "regex": "O/fzysN66GCB6jLDdcz9ba7CngDD3OFlItgTwwFCmrI+svmUkVvjOc20JA==",
    "maskPrefix": "APIKEY"
  },
  {
    "id": "api-key-github-pat",
    "category": "credential",
    "regex": "dKG90d1kx3uc7Aaxa8mYNu/R2EiG99ltbsNg5Q==",
    "maskPrefix": "APIKEY"
  },
  {
    "id": "api-key-gitlab",
    "category": "credential",
    "regex": "dKS52Nwrw0rQwjjHUNTvbp2GtR6NmKhr",
    "maskPrefix": "APIKEY"
  },
  {
    "id": "api-key-npm",
    "category": "credential",
    "regex": "fbik5vNHtVGctSPaB92fLPGdxBg=",
    "maskPrefix": "APIKEY"
  },
  {
    "id": "api-key-sendgrid",
    "category": "credential",
    "regex": "QI+Vl/NHtVGctSPaB92dep/Q2lWT1dg4DbBhwiFCuuM+8ZaU9X2qO9Hl",
    "maskPrefix": "APIKEY"
  },
  {
    "id": "connstr-server",
    "category": "credential",
    "regex": "O/fz6s107m6P5B2LXoWeJOj4hxDNy+FqHp4/7Gkzs/kulLqT81ijV466BME=",
    "maskPrefix": "CONNSTR"
  },
  {
    "id": "connstr-userid",
    "category": "credential",
    "regex": "O/fz7Ntj6leOshCOVrGrM+v3m0+C9Pc8Da93xDNNnfg=",
    "maskPrefix": "CONNSTR"
  },
  {
    "id": "internal-hostname",
    "category": "network",
    "regex": "SKnkw+krwjvQoQSxS8m4Fu/x2EiGhts7C9sQtmhQ+rp9vKzLxmf0d573K5pWiKM5vsKGEc3J6nMi2BD6",
    "maskPrefix": "HOST"
  },
  {
    "id": "credit-card",
    "category": "financial",
    "regex": "T6rhhpJa/HDJ5QLHdpefaOvQ2xjjzP8iK60u",
    "maskPrefix": "CARD"
  },
  {
    "id": "my-number",
    "category": "pii",
    "regex": "T6qV3dMy5VeOpwWOUdC/C7GUtAHEnPlKNA==",
    "maskPrefix": "MYNUM"
  },
  {
    "id": "bank-account",
    "category": "financial",
    "regex": "O/fzXCelfbFaf8xAz2t1KyckS4AFD61KJdsXon2AfElO95XKglr8cMq0YZc=",
    "maskPrefix": "BANK"
  },
  {
    "id": "bank-account-type",
    "category": "financial",
    "regex": "O/fzXzGocYtn5LxXuQF48Ov3m0/jzP8heskx",
    "maskPrefix": "BANK"
  },
  {
    "id": "passport-jp",
    "category": "pii",
    "regex": "T6qS+IVcxXDP5QWOUdO/C6A=",
    "maskPrefix": "PASSPORT"
  },
  {
    "id": "corporate-number",
    "category": "pii",
    "regex": "O/fzXxuTfLFHf8xAz2t1DCEqR4Y+BtkpCoJmw3qAfElO95XKgnrEaamxBY5R1fEq",
    "maskPrefix": "CORPNUM"
  },
  {
    "id": "jp-address",
    "category": "pii",
    "regex": "O/fzXzW3fLFRcdpXVgFOwCQeX4w+O/g+acupPOeGWHlvLHMVQYUlIhgixZZxuLdjh5vYSOPdvVAQtxHjckPzrvRURZCAOaVQo3vYRcllZbRAOQvkM0sGlLVw5MVpR//pSJS8je02qCah7WCsbKKeIvGb3FWS9PElZsgKxDVc8JIj5ZXMmzbeTc21YAWWdO+4fjK1Ho6EsGsNrTmtBV/yj2b9+orpWu08yKsYtl/S9WLz951cj+21S3+qEO10KvDjPpS8gO5A3leIq2mrGsmeIvGbriOPhb356mFhd/z2nP5Os/mVmTPl",
    "maskPrefix": "ADDR"
  },
  {
    "id": "jp-address-paren",
    "category": "pii",
    "regex": "O/fzXzW3fLFRcdpXVgFOwCQeX4w+O/g+acupPOeGWHlvLHMVQYUlIhgixZZxuLdjh5vYSOPdvVAQtxHjckPzrvRURZDzWu0/uKhpx3aR+xGE7bUej4S3aw0e8BBoMpuPZvyMiZgrxH7E3h+sdpHxZ/abxTnKm7QvEK05q3Au8P5PvfqJ7kCoJsR35XoHC37On9DZSYvV30ojxAmocjO15iD7iOXdMa04vMQs3B3R8wu3ktggjvXfSiPFCahwQpymKo6P//RzqzvJqHS2X9fyboT3nVaP6bQ7CoR/qAYp8P4qJ3UphekkkqG1BJEayPNiv/AH2TaB2Q==",
    "maskPrefix": "ADDR"
  },
  {
    "id": "jp-person-name",
    "category": "pii",
    "regex": "SJS8ipg2rVeIq23aGsmeIvvtriPj3cIvZsFhxDUpgZVVlbKLhDLlUN3ELbZf1/Jn8vbDTYCSrCl3Es0No+1Tr/VvUcVOthd3Gzbmls9hSrBWNJSMPABtg+GNpDLyhlVkby9tB0GTL3cbEdkDv1O+vlsJAfAI1GGn1hjZLzyKbnf6XX7FTLka4mgvJQ6SXybseYKzOcqbtCZjrTmrdF/w/k+98P/uQMR+u6Fp2ge4txGD7a44ltO1OmKM",
    "maskPrefix": "PERSON"
  },
  {
    "id": "jp-person-name-hira",
    "category": "pii",
    "regex": "SJS8ipg2rVeIq23aGsmeIvvtriPj3cIvZsFhxDUpgZVVlbKLhDLlUN3ELbZf1/Jn8vbDTYCSrCl3Es0No+1T+kiUvIqYMqkmoe1q2hPSn365msRRwg==",
    "maskPrefix": "PERSON"
  },
  {
    "id": "jp-person-name-nospace",
    "category": "pii",
    "regex": "O/fzUD2xcLtKfe53VgB/xyErbYMjAPjz6WapPNqIVGNvLHQpQJE8dxQQ7Qy2TL6+aTMOzDTUY4LmFfQ1PIt8WftfbcVOvjnjQyIlD5tVJMtu1wzdEk4ZhyoU/Bem8Vev9kJpUT+i5O5tEb5+mpgn5nNMfNXDThmosG3g5KTVVTerQrVfNK5+lmzkv3ykDFXzvk1Q4FkYMGqzQP199OG8Oot3IDoAen2ldHHaQlYBbN4nK2UZWAsr/9VZMH3yzilQu7QgPiblGI4UG/GWw2NMsV86lIAyK2OC5o2pFcOKTkxvLVkwTpo0dxst3AOtar6xcwsP8Q/UYr/dF9A0PIpxYvZHasVPmSvuSgUlD6NpJcNy1w3VME0ziyoZ2zyn+3Cv9npoXjy25O5DFLF9jpglyHFPUvDDThmHsknG5KjQUTuEbLVcNYR+l1HksGuKDFXzvkJ191k0LGq+Zuh8+vq8O7Z3LyQ5en+tcn/NWlYBZv0lP1gZWxAN8ONXMHDXyyVdjLQsCwngBKeBfsRUzXByKyYTRYAINfjy7lylH84TJV2ML10J1OMohBQf15bMelUrJAhGGVgDPfPQdDBxx/4lfoO0LCsk4Qy7gXzhR89XdCsnJXcZWxAp8cJBMHz45SdHo7QgEjDgBKOBcNZvz2pdKyQ3ZYw8APjwy3ipKfETJV+ELlQo1OMejhoM6ZbMeXyzeD6UgDIrbIffjaghxYt/Tm8ueQ1BgRZ3GDbQAr1AvrBqGQ37HNRhs/MX0Qk8inhR9n9UxU2xBe5yOyUMtkglw3LXDs0VTTWnKhTuD6f7cK/2f2xRP6Lk7U86vn6amCriZk5158NBP4SxZfzkpctnOpRGtV8dmn+fTeS+fpoCX8a+TUzoWDw0arNI/3HH4bw3q2UsCBl6fpZM5LF9jgJe+75ORstaHApqs3fJffHevDagfi4tGHp9m3R97ndWDUXZJyRLGVcNO/HCQTB/2dIkaYa0LB0P7j20gX/fYMJUdSsqO0GAMTf4//1pqwzwEyV9vS9dCdTvFocaDOmWwmtIsXMLlIECOG2R2I2rB+KKc2VvLlQHTbYmdxg42ZbPa2aydTaUgyc3bZHYjaog4YZDe28uVChPkih3GhH+A61qvrBLLA3UDtRgrtwYyxY8hlZx9kdqxU2iP+5cAiUPm1Un0UfXDdIiThmHKhTjIqf7cK/2Z3NfFqLk70URvESvmCvCdU5b08NBJ7mxZfzkp/BzNId4tV8+tnyxaOS9UaAAeMK+TkjlWicnarBD/3HH4bw6tWQsGRx6fblUf81aVgFeyCcaYxlWLRby7GQwfvDXJGmGtC4tGOMXqIFw1m/DY0wrJw9PgQYtYKnLjagg+IpxYm8hYiFNtyl3GDb3DLZIvrJzGgzdNNRjieUUwgc8iW119Fx5xUGTL+xpKCUMm0Qm70jXDcEYTTegKhT8F6Xcdq/6Y1FQL4jk70ESv3ebmCbuR09X+Fg8NGqwQfR/1N+8NId4IQcSenC1RuS9UaACX8a+TX/AVi8KarBt5Hz45Lw7nlotAz16frtFcd5kVgFs+SccdRlaGAvw5FMwfuH+JV2MtCw1P+MvloF+7HbPa2ErKi9vgisY+P7mRqkX4xMlTpEtRhrU4yG4Ggzpls1wcrFLK5SDHxFiivqNqiriEyZqvC1+JNTjNoIaDOmWw2NMsFYblI0wImGK5o2kJvuJXH9vLXk2TbcpdxgR1A+deb6xVCIA8hvUYrfHFtgoPIhfcfpPR8VNtDHuSRZwwhXe6mjjSGnwXCoXarBW1OSm30+v9WZ2xU2DEOxpByUDqUwrwnXXAM8NQRGhKhboJqn6d6/1QUlQPbHk4mQ6sH+dmCfmQkJ90sNNKrK/ZPvkpNBCOoZ/tV0QvXywRrECtl/X8mf3951Wi5i0OwqEdd4GKZymVfH5iYVa7U283h+3A5/ze/HW",
    "maskPrefix": "PERSON"
  },
  {
    "id": "jp-person-name-list",
    "category": "pii",
    "regex": "SJS8ipg2rVeIq23aGsmeIvvtriPj3cIvZsFhxDUpgZVVlbKIhDLlI8KiAgmqZe4KmfedVo+YsUojwniocEKcpiqOj//0c94yzah0tl+igxGE9pNUk5z5Py3DYOU=",
    "maskPrefix": "PERSON"
  },
  {
    "id": "jp-person-name-honorific",
    "category": "pii",
    "regex": "SJS8ipg2rVeIq23aGsmeIvvtriPj3cIvZsFhxDUpgZVVlbKLhDDlI8Kiumu/B0DEvk1P/cNONJkqF+InPIpFW/RcVsVBhTDiaC8lAoBWK8J11w/BAUERoSoXxRip+nev+lFrUD2x5O5MGLB/nZgn+WZCfdLDTDuUv2T75KTXezeoc+A=",
    "maskPrefix": "PERSON"
  },
  {
    "id": "jp-person-name-spaced-honorific",
    "category": "pii",
    "regex": "SJS8ipg2rVeIq23aGsmeIvvtriPj3cIvZsFhxDUpgZVVlbKIhDDlUN3ELbZf1/Jn8vbAWoVLBYO1c9/kpshYr/V4RsVOqCd3GB3RDb5763/9lrM5zIRnltcSzBqv00mPOpSUVhSOxCMeGfcJq0sh1k5IavdcKS/110mvGsKMQXtOtO2Q",
    "maskPrefix": "PERSON"
  },
  {
    "id": "jp-label-name",
    "category": "pii",
    "regex": "O/f1hIA5ou1NF7x6p5gnx09OYejDTg+Ts0zfcMDq/6/3c2pRCa5wi3inJQOqRyXiY05t7Vo4CSl/rT+yG1X6j2aOj4jpW8R417Fx1RC/niLxm9hQ4923ImbBYcQ1VoaVVZS8/5E2qCah7R+rbKKfLPCH3hjk9Pf11nERs2lQm49m+/mJnVrtOMmoacd2kfsRhO20EPmRtCZ7rTneASmGjmj65Y/VLqcxpsQqCapkn3yZ951Wj5ixSiPCeKhwQpymKo6P//Rz3jLNqHS2X6KDEYT2k1STnPk/aQ==",
    "maskPrefix": "PERSON",
    "defaultConfidence": 0.9
  },
  {
    "id": "jp-label-address",
    "category": "pii",
    "regex": "O/f1hIA5ou9AF79jqpgk3kJOdM1aNDRqs0DJfP3gJU+jtC42FuIlhBsR2cN2l+gM+JG0EPnutVcLrT+yaUf/6UiUvIqYNq1XiKtt2hrJniL77a4j4923JmLBYcQ1XPDqVZS8iphHqCah7WrabKLyevtEVPWSRziPC4p+tHNfvfo=",
    "maskPrefix": "ADDR"
  },
  {
    "id": "jp-label-phone",
    "category": "pii",
    "regex": "O/f1hIA5ouJmI7FDmwNX/SckX1rD/MFaKoUp9DyJUGn2cGZePax9hEqnJQOqRyXiY05t7Zb09zwNy3bENSmG4lKVlcqCL8RvpsQ9x3ef9Xvzn5U=",
    "maskPrefix": "TEL"
  },
  {
    "id": "zairyu-card",
    "category": "pii",
    "regex": "SInk4/V9qnah/CLSV7+Depj2k1fC",
    "maskPrefix": "ZAIRYU"
  },
  {
    "id": "basic-pension",
    "category": "pii",
    "regex": "T6yyjdVdteh+JLZWp7meM7mdlQ==",
    "maskPrefix": "PENSION"
  },
  {
    "id": "driver-license",
    "category": "pii",
    "regex": "T6yyiJp7",
    "maskPrefix": "LICENSE"
  },
  {
    "id": "url",
    "category": "network",
    "regex": "e7y9yds5oiTSwwe2Wdj8cOD3wTni9a8=",
    "maskPrefix": "URL"
  },
  {
    "id": "crypto-eth",
    "category": "credential",
    "regex": "I7CS2IVg2Sa7qHTTd5/2Z78=",
    "maskPrefix": "CRYPTO"
  },
  {
    "id": "crypto-btc",
    "category": "credential",
    "regex": "SPn65PNntWCQtSOrB6yIeoz7xT+Ohb1LLcN5tHNbvQ==",
    "maskPrefix": "CRYPTO"
  },
  {
    "id": "iban",
    "category": "financial",
    "regex": "SInk4/V9qnah/CLYV7+DepibxVzi07BrCpU3rz00gf5J+OSA9X2oJ8yuJA==",
    "maskPrefix": "IBAN"
  },
  {
    "id": "jumin-code",
    "category": "pii",
    "regex": "T6yyiJl7",
    "maskPrefix": "JUMINCODE"
  },
  {
    "id": "amount-yen",
    "category": "business",
    "regex": "SPjkgEe6CCYSJMDGxVhOCrmaxFSK1d/y7napHMSKRVVO9yw/Lg==",
    "maskPrefix": "AMOUNT"
  },
  {
    "id": "amount-yen-kanji",
    "category": "business",
    "regex": "SCxxOUy8FO9FEbxxsQB4wycuRYEHK2GT/RX1BaXiQTSKdiw0K+IgjBgc3Q+vYp8s8IfQGFouAg==",
    "maskPrefix": "AMOUNT"
  },
  {
    "id": "date-jp-era",
    "category": "business",
    "regex": "O/fzXROifZlx5LxTmQJKx75NcMhaOghqs1Xrfu3MvDWLRi8LEy/D7ngbaccTC37H70RU/OLTtTpljKkh9Ef/6Uj45IBHuggmEiTAt1HV7mW/TXTtlpesKWyqfLV5gHxDPid1IPV9qSfP5b99j839",
    "maskPrefix": "DATE"
  },
  {
    "id": "date-iso",
    "category": "business",
    "regex": "IfiSiYU/xXDP5QLHBbmZZ/P21z6Phb1LDdxjxRtf7eBO95KJhT/F",
    "maskPrefix": "DATE"
  },
  {
    "id": "postal-code-jp",
    "category": "pii",
    "regex": "8Ehb4pgroVaGqyTHcdTvbp/Q3Bg=",
    "maskPrefix": "POSTAL"
  },
  {
    "id": "phone-jp-fullwidth",
    "category": "pii",
    "regex": "I5P5lJFb4zrRrCSxxVhPtEEXtT6Phb1LLcBgrD00L2+eK0oF9V2oJsTFIt5X",
    "maskPrefix": "TEL"
  },
  {
    "id": "jp-furigana-name",
    "category": "pii",
    "regex": "SCd1MYBbw+h8GXQJqHefLPCH3hjkiNhitXHMxRuMQVI+K0sq9X2qJ8vlAgWWbesK",
    "maskPrefix": "PERSON"
  },
  {
    "id": "jp-katakana-name",
    "category": "pii",
    "regex": "O/f1mPPlGqrQe9peyWd+CuvwC+cehWeV4hLPJB0U8v8rtZKZ9HJ7i33FAgmoRe+0QR8L5gP1/yR6yTGwf06bMJFp5ForsnuIQcVw",
    "maskPrefix": "PERSON"
  },
  {
    "id": "jp-name-nakaguro",
    "category": "pii",
    "regex": "O/f1mPNa7TjNqGy2X9f2Z/KGtBCG7sJQCoQKoXBf7Y9mjoj/7luxUKHtatoa0Z4i8Z/YVZL08S8QtwrENSn54yPllczuR95NoONoxh6ZIdR58LQQjJi0IwqEf6xwX+2PZvGP/+5a7U3EqGnHdpGEFoTttR6OhLBrfs5twxwa8+Mj/ZXMmzKoO9DELNNsooQLt+3RVY+F2GMQsAreHUY=",
    "maskPrefix": "PERSON"
  },
  {
    "id": "jp-person-name-fullspace",
    "category": "pii",
    "regex": "O/fzUD2xcLtKfe53VgB/xyErbYMjAPjz6WapPNqIVGNvLHQpQJE8dxQQ7Qy2TL6+aTMOzDTUY4LmFfQ1PIt8WftfbcVOvjnjQyIlD5tVJMtu1wzdEk4ZhyoU/Bem8Vev9kJpUT+i5O5tEb5+mpgn5nNMfNXDThmosG3g5KTVVTerQrVfNK5+lmzkv3ykDFXzvk1Q4FkYMGqzQP199OG8Oot3IDoAen2ldHHaQlYBbN4nK2UZWAsr/9VZMH3yzilQu7QgPiblGI4UG/GWw2NMsV86lIAyK2OC5o2pFcOKTkxvLVkwTpo0dxst3AOtar6xcwsP8Q/UYr/dF9A0PIpxYvZHasVPmSvuSgUlD6NpJcNy1w3VME0ziyoZ2zyn+3Cv9npoXjy25O5DFLF9jpglyHFPUvDDThmHsknG5KjQUTuEbLVcNYR+l1HksGuKDFXzvkJ191k0LGq+Zuh8+vq8O7Z3LyQ5en+tcn/NWlYBZv0lP1gZWxAN8ONXMHDXyyVdjLQsCwngBKeBfsRUzXByKyYTRYAINfjy7lylH84TJV2ML10J1OMohBQf15bMelUrJAhGGVgDPfPQdDBxx/4lfoO0LCsk4Qy7gXzhR89XdCsnJXcZWxAp8cJBMHz45SdHo7QgEjDgBKOBcNZvz2pdKyQ3ZYw8APjwy3ipKfETJV+ELlQo1OMejhoM6ZbMeXyzeD6UgDIrbIffjaghxYt/Tm8ueQ1BgRZ3GDbQAr1AvrBqGQ37HNRhs/MX0Qk8inhR9n9UxU2xBe5yOyUMtkglw3LXDs0VTTWnKhTuD6f7cK/2f2xRP6Lk7U86vn6amCriZk5158NBP4SxZfzkpctnOpRGtV8dmn+fTeS+fpoCX8a+TUzoWDw0arNI/3HH4bw3q2UsCBl6fpZM5LF9jgJe+75ORstaHApqs3fJffHevDagfi4tGHp9m3R97ndWDUXZJyRLGVcNO/HCQTB/2dIkaYa0LB0P7j20gX/fYMJUdSsqO0GAMTf4//1pqwzwEyV9vS9dCdTvFocaDOmWwmtIsXMLlIECOG2R2I2rB+KKc2VvLlQHTbYmdxg42ZbPa2aydTaUgyc3bZHYjaog4YZDe28uVChPkih3GhH+A61qvrBLLA3UDtRgrtwYyxY8hlZx9kdqxU2iP+5cAiUPm1Un0UfXDdIiThmHKhTjIqf7cK/2Z3NfFqLk70URvESvmCvCdU5b08NBJ7mxZfzkp/BzNId4tV8+tnyxaOS9UaAAeMK+TkjlWicnarBD/3HH4bw6tWQsGRx6fblUf81aVgFeyCcaYxlWLRby7GQwfvDXJGmGtC4tGOMXqIFw1m/DY0wrJw9PgQYtYKnLjagg+IpxYm8hYiFNtyl3GDb3DLZIvrJzGgzdNNRjieUUwgc8iW119Fx5xUGTL+xpKCUMm0Qm70jXDcEYTTegKhT8F6Xcdq/6Y1FQL4jk70ESv3ebmCbuR09X+Fg8NGqwQfR/1N+8NId4IQcSenC1RuS9UaACX8a+TX/AVi8KarBt5Hz45Lw7nlotAz16frtFcd5kVgFs+SccdRlaGAvw5FMwfuH+JV2MtCw1P+MvloF+7HbPa2ErKi9vgisY+P7mRqkX4xMlTpEtRhrU4yG4Ggzpls1wcrFLK5SDHxFiivqNqiriEyZqvC1+JNTjNoIaDOmWw2NMsFYblI0wImGK5o2kJvuJXH9vLXk2TbcpdxgR1A+deb6xVCIA8hvUYrfHFtgoPIhfcfpPR8VNtDHuSRZwtl/X8mfyg9dfl5el9ddkrxrTEyZ0i7QvCSd6fqVC5LxvogNWyL5Ca81WPTNqvlv+cdXYvDS3diAsH3p+gn1xzF1WDVv1Kz5fGVoZBP/DRjB97sspRqS0LQYq7w28gXzhUc5feX6Z951Wj5ixSiPCeKhwQpymKo6P//Rz3jLNqHS2X6KDEYT3nVaPnLU7CoR/qHlZnfpo+eWN1Q==",
    "maskPrefix": "PERSON"
  },
  {
    "id": "jp-company-name",
    "category": "pii",
    "regex": "O/fzXwisfbdyfOVwzUB8KyQ3YYwmOGCqzBboJjyKUFv2WEVdFJx/r0PkvHqiDHHQJhdyghsWrU0KhH+ocFqcpiD8+YmFWu0yu94ftl+ihGH0hrQQ+e69UAqEf6gBX+2PZvv5/+5a7U27qmjHdpGEEfHqqUjlyalsZtx1e8PUnagh5PuJ1XrDV4iradofuLdk9pvYSOPdvVAQtxDtBin25T6UvP/uP95XiKtpqxrJniLxm64j493CUGTAYcQ1KYbgUonk48kr4jvQobppkbm5Ze6Z2BiXl77w9lupJM+LfEn0bHfFTpoR4mQIvVawA2bpvk547Vo4CPLqa6s8/hMlQ5sgej5MugLsWSYlBZZsJPdoRFTsw/Ss8PZbELFp",
    "maskPrefix": "COMPANY"
  },
  {
    "id": "birth-year-jp",
    "category": "pii",
    "regex": "O/fziJF6qjvUw2nHE7m5Zb9OUdFYPBv110+vGsw=",
    "maskPrefix": "BIRTHYEAR"
  },
  {
    "id": "date-jp-full",
    "category": "business",
    "regex": "SPjkgPV9rHYYIe2xGsn7CrmaxFfCThieDcFhoR0U8f8htS8uDQ==",
    "maskPrefix": "DATE"
  }
];

export const SURNAMES = '+l1+URixfbxg5L1XugdC0iQ3QBlaFxPz8murDPATJG6DIF4d1O8QvxsE8ZbDT1qxayCUgisYYK77jagkyodXd28ucRhAuCJ3GCnoDLZIvrN6Bg74LtRhptkX0g88ikpz+19txU2WEexpKCUPm1Ulw3LXDvgBThi6KhX2DaTXSq/1VGFfNZfk7WsWsX2OmCTvR01Y0cNNNaezRcLkqfd/OpBgtVwGj3GIVeS8RKMBQtq+TEvKVissarND7XHDx7w6lEYqOS3vG6OBcd5kzHlTKycma4IrGPjz23KpFt8TJUOaLlUV1OAtjhQf15bMVWKwVhuUgxYjYor6jakp8YpPcG8vVgpNsQV3GBHUDb5UvrJyJA3SItRsgfIW2Cg8inJy9Fx5xU24FONqPCUNtVcm7VfXDvguTDycKhnzCaj4ZK/2VUtfNKrk4nw4sX2OmCvKUE10zcNAE7KyS9nkqMp/NY5ZtV4OiX+fTeS8ToADVue+T1DsWR0iar5m6H3O8Lw2oWkvJQR6fpZDf81aVgB6+iccdRlbECn/0X8wfc7wJ0ejtCwJJ+8fhYF+x31WAmH5vkxD3FouAWq/dt197f+8NoFELi0YenyzUH3qXFYBTMi+T1DIWDw0arJJxn/U37w6uFAvJQB6cIR4fdd1VgJe2isoQBlZNQ3z50Awfcz4Jk6CtCw/LeEMu4F+xFTOXlcrJyZrjS4h+PLvdKgn3RMmY6chTjfU4zaCFQ/9ls1McLJcCJSAGg1ii8eNqSDCindOby1+JE2JO3cbBPUNvlS+sWoBDdQO1GG0wRbYKDyKd3b7X23FTrQ67GkoJQKfQCfKQNcB3i1PEKYqFOg/qehOr/V9VV48tuTsaSi/d7uYJPNPTHzVw009pb92wuSk1202onm1XzW35ONqPL92hpgn+WxOXOvDTQKTs0D95KXcdjSHeLVcOI99vGDksG2kAU30vkNN2lg8NGqxaPF8+vq8NrdvIRwXen+Nd3DpXVYMUv4nJXcZVgMc8cJBMH3uwSdHo7QgNyThDLuBcNZgzFViKyYWeIw4JvjxyVOpK/YTJk6tLXkH1OM4i4F91k7PU18rJDN3jDgm+PDuUKUb6BMmToIvXQnU4RGsFB/Xls1tRbJzGpSBByJtkdiNpQ7iik9wby1tHk2nAncYKegPrGG+snU2Dvgu1GG57BbYKDyKb2n1dm3FTL4R7lMdJQO/UyfkdNcBxhBPEKYqFtMrp/twr/VeeV0Sk+TvRhK9UL+YJ/dCTmfGw042pb92wuSpyWw2s3y1XBqvf59N5Lx2tQFz3L5CbfdbEhFqsEH0fPr6vDSHeCw2C3pwhHhx3mRWAWbwJhJtgQA1+PLuSakp8RMpeIsteAjU4zalGwT1ls9Vc7N6IJSCIBthmMmNqjXmiFRjbyFcDk+SKHcbKfkOkm6+smYMDdYJ1GGm2RT/LjyGa0v6T0fFTLoS7WApJQ6TYSboX0x81cNONK6xZfzkp/twO61ytVEWveTvRhK/d7uYJMBnQm/rw04YvrJJx+So4lI3qV21Xxi+cYxz5LxEhAF1yr5OWOpZGiZqsFDdfc7wvDafXywONXp+vmF91klWDEbQJT9YGVcYM/PZUjB93e0lXLC0LAAb4Qy7gX/NWsxtQiskC1GDIwT48ORTMH75wCVkjrQsFyHhDLuBcd5kzXByKyokYoAjGPj+6EqqBOwTJWOcLXgI1OMRhhgvxJbMcku/VQ+Ugx45Y4LmjasH4oZHXW8texBNshY=';

export const HONORIFICS = '8ElcWiqV5O1aACUMmmu+sWwUlIA6IGOCyY2lG+iGVWRvIGMLQZMvdxo85wO/U76xSysB8AjUbY/0GNkvPIpxU/pdfsVNqDziaC8lDpVmK8J11wzdBEw/rQ==';

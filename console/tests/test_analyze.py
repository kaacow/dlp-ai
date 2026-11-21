import sys; sys.path.insert(0, "app")
from features.globalsearch.analyze import *
w = Watch(parse_list("jdoe\notheruser\na.gasimov\nbi_alias=asmuser\nsales\n")[0])
T = [
 ("CORP\\jdoe", "otheruser", "alert", [], ["otheruser"]),
 ("CORP\\jdoe", "\r\notheruser\r\n", "alert", [], ["otheruser"]),
 ("CORP\\jdoe", "jdoe", "ok", ["jdoe"], []),
 ("CORP\\JDoe", "JDOE.", "ok", ["jdoe"], []),
 ("CORP\\jdoe", "jdoe\r\notheruser", "review", ["jdoe"], ["otheruser"]),
 ("CORP\\jdoe", "promo 12345 galbani", "unknown", [], []),
 ("CORP\\jdoe", "otherusers", "unknown", [], []),          # no substring matches
 ("CORP\\jdoe", "", "none", [], []),
 ("CORP\\jdoe", "  \r\n ", "none", [], []),
 ("CORP\\asmuser", "bi_alias", "ok", ["bi_alias"], []),     # alias: bi01 login differs from Windows name
 ("CORP\\jdoe", "bi_alias", "alert", [], ["bi_alias"]),
 ("CORP\\x", "CORP\\otheruser", "alert", [], ["otheruser"]),
 ("CORP\\x", "a.gasimov", "alert", [], ["a.gasimov"]),
 ("CORP\\x", "user: a.gasimov.", "alert", [], ["a.gasimov"]),
]
bad = 0
for u, t, v, o, f in T:
    r = analyze(u, t, w)
    if r != (v, o, f): bad += 1; print("FAIL", u, repr(t), r, "expected", (v, o, f))
sn = snippet("asmith Hunter2pass! Tmp@123456 " + "x " * 30, Watch([("asmith", "")]))
assert "Hunter" not in sn and "2pass" not in sn and "123456" not in sn and "asmith" in sn, sn
print("snippet:", sn)
print(parse_list("a\nb=c\n#x\nbad name!\nd,extra\n﻿e"))
S="bi.example-corp.com"
B="bi.example-corp.com Example Corp BI - Edge"
J=[("CORP\\jdoe","otheruser",B,"\r\notheruser\r\n","alert"),("CORP\\otheruser","otheruser",B,"otheruser","ok"),
   ("CORP\\jdoe","otheruser","Gmail - Edge","otheruser",None),            # not bi01
   ("CORP\\jdoe","otheruser",B,"otherusers",None),                        # part of a longer word
   ("CORP\\asmuser","bi_alias",B,"bi_alias","ok"),("CORP\\jdoe","bi_alias",B,"x bi_alias",  "alert"),
   ("CORP\\JDoe","jdoe",B,"JDOE","ok")]
for u,k,t,x,v in J:
    r=judge(u,k,t,x,w,S)
    if r!=v: bad+=1; print("JUDGE FAIL",u,k,r,v)
print("failures:", bad, "of", len(T)); sys.exit(bad)

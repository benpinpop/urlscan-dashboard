"""Tests for the query-term list behind the query bar's autocomplete."""

import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from query_terms import QueryTerms  # noqa: E402

HEADER = "field,group,type,plan,regex,description,example\n"


class QueryTermLoaderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def write(self, text, encoding="utf-8"):
        path = pathlib.Path(self.tmp.name) / "terms.csv"
        path.write_text(text, encoding=encoding)
        return path

    def test_shipped_list_loads(self):
        terms = QueryTerms.load()
        fields = [term.field for term in terms.terms]
        self.assertGreater(terms.size, 100)
        self.assertEqual(len(fields), len(set(fields)))
        self.assertIn("page.domain", fields)
        self.assertTrue(all(term.plan in {"free", "pro"} for term in terms.terms))
        self.assertTrue(all(term.regex in {"true", "false"} for term in terms.terms))

    def test_quoted_examples_keep_their_commas_and_quotes(self):
        path = self.write(
            HEADER
            + 'asnname.keyword,network,keyword,free,false,"AS names, exact.",'
            + '"asnname.keyword:""CLOUDFLARENET, US"""\n'
        )
        (term,) = QueryTerms.load(path).terms
        self.assertEqual(term.description, "AS names, exact.")
        self.assertEqual(term.example, 'asnname.keyword:"CLOUDFLARENET, US"')

    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            QueryTerms.load(pathlib.Path(self.tmp.name) / "nope.csv")

    def test_missing_columns_raise(self):
        with self.assertRaises(ValueError):
            QueryTerms.load(self.write("field,description\ndomain,Any domain\n"))

    def test_file_with_no_usable_rows_raises(self):
        with self.assertRaises(ValueError):
            QueryTerms.load(self.write(HEADER + ",x,keyword,free,false,blank field,\n"))

    def test_bad_rows_are_skipped_and_values_normalised(self):
        path = self.write(
            HEADER
            + "domain,domain,domain,free,false,First.,domain:a.example\n"
            + "domain,domain,domain,pro,false,Duplicate.,domain:b.example\n"
            + ",x,keyword,free,false,No field.,\n"
            + "<img src=x>,x,keyword,free,false,Junk field.,\n"
            + "brand.name,brand,text, PRO ,TRUE,Pro row.,brand.name:paypal\n"
            + "short,general,keyword,,,,\n",
            encoding="utf-8-sig",  # a BOM must not corrupt the first header
        )
        terms = {term.field: term for term in QueryTerms.load(path).terms}
        self.assertEqual(list(terms), ["domain", "brand.name", "short"])
        self.assertEqual(terms["domain"].description, "First.")
        self.assertEqual(terms["brand.name"].plan, "pro")
        self.assertEqual(terms["brand.name"].regex, "true")
        self.assertEqual(terms["short"].plan, "free")
        self.assertEqual(terms["short"].example, "")


if __name__ == "__main__":
    unittest.main()

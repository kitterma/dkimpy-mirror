import unittest
import doctest
import dkim
import arc
from dkim.tests import test_suite
from arc.tests import test_suite as arc_test_suite

doctest.testmod(dkim)
doctest.testmod(arc)
unittest.TextTestRunner().run(test_suite())
unittest.TextTestRunner().run(arc_test_suite())

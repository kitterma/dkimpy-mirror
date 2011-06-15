import unittest
import testutil
import testsign

def suite():
  s = unittest.TestSuite()
  s.addTest(testutil.suite())
  s.addTest(testsign.suite())
  return s

if __name__ == '__main__':
  unittest.TextTestRunner().run(suite())


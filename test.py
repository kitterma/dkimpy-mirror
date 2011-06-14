import unittest
import testutil

def suite():
  s = unittest.TestSuite()
  s.addTest(testutil.suite())
  return s

if __name__ == '__main__':
  unittest.TextTestRunner().run(suite())


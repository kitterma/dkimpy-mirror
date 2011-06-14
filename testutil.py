import unittest
from dkim.util import parse_tag_value

class ParseTestCase(unittest.TestCase):

  def testParse(self):
    hval = '''v=1; a=rsa-sha256; d=facebookmail.com; s=s1024-2011-q2; c=relaxed/simple;
        q=dns/txt; i=@facebookmail.com; t=1308078492;
        h=From:Subject:Date:To:MIME-Version:Content-Type;
        bh=+qPyCOiDQkusTPstCoGjimgDgeZbUaJWIr1mdE6RFxk=;
        b=EUmDmdnAsNtjSEHGHNTa8PXgGaEUtOVezagmninX5Bs/Q26R9r3AMgawyUSKkbHp
        /bQZU6QPZfdvmLMPdIWCQPo8SP+gsz4dpox2efO61DlvgYaxBRhwFedAW9LjYhQc
        3KzW0yB9JHwiDCw1EioVkv+OMHhAYzoIypA0bQyi2bc=;
'''
    sig = parse_tag_value(hval)
    print sig

def suite(): 
  s = unittest.makeSuite(ParseTestCase,'test')
  return s

if __name__ == '__main__':
  unittest.TextTestRunner().run(suite())

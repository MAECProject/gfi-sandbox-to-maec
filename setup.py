from setuptools import setup, find_packages

setup(name='python-maec',
      description='latest set of MAEC and CybOX bindings from MAEC (http://maec.mitre.org) tools repository',
      author='MITRE',
      author_email='maec@mitre.org',
      url="https://github.com/MAECProject/Tools",
      maintainer="Roberto Martelloni",
      maintainer_email="rmartelloni@gmail.com",
      version='0.0.1',
      py_modules=['maec'],
      long_description="""Python bindings for MAEC (http://maec.mitre.org) & CybOX (http://cybox.mitre.org/). """,
      keywords="maec CybOX",
      license="http://maec.mitre.org/about/termsofuse.html, http://cybox.mitre.org/about/termsofuse.html",
      packages=['maec','cybox'],
      package_dir={'': 'Bindings/Python'}
      )

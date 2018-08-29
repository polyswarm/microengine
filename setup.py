from setuptools import setup




setup(
    name='microengine',
    version='0.1',
    description='Collection of sample microengine implementations and a basic microengine framework',
    author='PolySwarm Developers',
    author_email='info@polyswarm.io',
    url='https://github.com/polyswarm/microengine',
    license='MIT',
    include_package_data=True,
    packages=['microengine'],
    package_dir={
        'microengine': 'src/microengine',
    },
    package_data={
        'microengine': ['test_data/keyfile'],
    },
    entry_points={
        'console_scripts': ['microengine=microengine.__main__:main', 'microengine-unit-test=microengine.testbase:main'],
    },
)

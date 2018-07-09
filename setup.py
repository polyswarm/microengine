from setuptools import setup


def parse_requirements():
    with open('requirements.txt', 'r') as f:
        return f.read().splitlines()


setup(
    name='microengine',
    version='0.1',
    description='Collection of sample microengine implementations and a basic microengine framework',
    author='PolySwarm Developers',
    author_email='info@polyswarm.io',
    url='https://github.com/polyswarm/microengine',
    license='MIT',
    install_requires=parse_requirements(),
    include_package_data=True,
    packages=['microengine'],
    package_dir={
        'microengine': 'src/microengine',
    },
    entry_points={
        'console_scripts': ['microengine=microengine.__main__:main'],
    },
)

from distutils.core import setup

setup(
    name='siwe',
    version='0.1.0',
    author='Spruce Systems, Inc.',
    project_urls={
        'Homepage': 'https://login.xyz',
        'Source': 'https://github.com/spruceid/siwe-py',
        'Discord': 'https://discord.gg/Sf9tSFzrnt',
        'EIP-4361': 'https://github.com/ethereum/EIPs/blob/master/EIPS/eip-4361.md'
    },
    packages=['siwe', ],
    license='MIT',
    description='A Python implementation of Sign-In with Ethereum (EIP-4361).',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
)

# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = 'HackTheBox Writeup'
copyright = '2023. Writeups by zhsh are licensed under CC BY-NC-SA 4.0'
author = 'zhsh'
release = '0.0.2'
language = 'en'

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    'myst_parser',
    'sphinx_markdown_tables'
]

templates_path = ['_templates']

exclude_patterns = []

source_suffix = {
    '.rst': 'restructuredtext',
    '.txt': 'markdown',
    '.md': 'markdown',
}

master_doc = 'index'

# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

# html_theme = 'alabaster' # Defualt theme.
html_theme = 'sphinx_rtd_theme'
html_static_path = ['_static']

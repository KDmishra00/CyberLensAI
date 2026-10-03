"""CyberLens AI core pipeline modules.

The pipeline order is: upload -> parser -> preprocess -> analyzer ->
security -> stats -> report. Each module is plain functions on pandas
DataFrames / dicts so the flow is easy to follow top to bottom.
and other stuff 
"""

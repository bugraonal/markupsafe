# Mayhem Integration
Markupsafe project has been intergrated into Mayhem fuzzing framework. Markupsafe is a Python module used to safely add escape charaters to plaintext for markup files. It can also strip escape charaters markup text. Prior to this integration, the project was tested using unit tests.

## Harnessing
Markupsafe is a Python module. It does not have a seperate executable, which makes it incommpatible with Mayhem's defualt integration method. 

In order to fuzz Markupsafe with Mayhem, Google's Atheris Python module for fuzzing was used. This module uses libfuzz, which can be used by the Mayhem.

Atheris requires a Python script to be prepared for each Mayhem command. 2 such scripts were prepared;
    - [Escape function fuzzer][escape_fuzzer.py]
    - [Unescape function fuzzer][unescape_fuzzer.py]

The escape function takes in a string and escapes any characters/sequences that would need be escaped in a markup file. 

The unescape function takes in a escaped markup string and converts it to plain text.

To test these functions the scripts fuzz with unicode characters. To generate coverage data, the modules are imported with Atheris' instrument_imports() method.

A [Dockerfile][Dockerfile] along with a Docker image has been prepared for testing. The image is based on the [fuzzers/atheris][https://hub.docker.com/r/fuzzers/atheris] image. It copies the repo and the Mayhem files to the image. 

A [Mayhemfile][Mayhemfile] is prepared to run using Mayhem's framework. It runs the 2 scripts according to Mayhem's specifications.

The Docker image generation and Mayhem runs are automated using Github workflows. The project had exxisting workflows for executing the unit tests. A new workflow was created for Mayham workflow. This workflow uses the template provided by the Mayhem hackathon resources. The results of the flow can be seen in the repo's actions page, where the output will contian a link to the Mayhem run.

## Results


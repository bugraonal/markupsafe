# Mayhem Integration
Markupsafe project has been intergrated into Mayhem fuzzing framework. Markupsafe is a Python module used to safely add escape charaters to plaintext for markup files. It can also strip escape charaters markup text. Prior to this integration, the project was tested using unit tests.

## Harnessing
Markupsafe is a Python module. It does not have a seperate executable, which makes it incommpatible with Mayhem's defualt integration method. 

However, one aspect of this project makes it especially interesting for fuzzing; the implementation of the main logic is done in both Python and C. During the installation, if the build tools detect building C program capability, a shared library object will be created and Python bindings will be used.

### Harnessing Scripts
In order to fuzz Markupsafe with Mayhem, Google's Atheris Python module for fuzzing was used. This module uses libfuzz, which can be used by the Mayhem.

Atheris requires a Python script to be prepared for each Mayhem command. 2 such scripts were prepared;
    - [Escape function fuzzer][escape_fuzzer.py]
    - [Unescape function fuzzer][unescape_fuzzer.py]

The escape function takes in a string and escapes any characters/sequences that would need be escaped in a markup file. 

The unescape function takes in a escaped markup string and converts it to plain text.

To test these functions the scripts fuzz with unicode characters. To generate coverage data, the modules are imported with Atheris' instrument_imports() method.

### Dockerfile
A [Dockerfile](Dockerfile) along with a Docker image has been prepared for testing. The image is based on the [oss-fuzz-base-builder-python](gcr.io/oss-fuzz-base/base-builder-python) image. The Dockerfile copies the repo and the Mayhem files to the image. 

In order to properly analyze the C implementations the base Docker image inserts the compilation flags for libfuzz in the CFLAGS environmental variable.

### Mayhemfile
A [Mayhemfile](Mayhemfile) is prepared to run using Mayhem's framework. It runs the 2 scripts according to Mayhem's specifications.

In order to make the fuzzing more effective, a [dictionary file](hmtl.dict) has been provided in the Mayhemfile. This let's Mayhem generate fuzzed inputs using the keywords that appear in this dictionary. In this case, the dictionary file contains HTML keywords.

### Workflow
The Docker image generation and Mayhem runs are automated using Github workflows. The project had existing workflows for executing the unit tests. A new workflow was created for Mayham workflow. This workflow uses the template provided by the Mayhem hackathon resources. The results of the flow can be seen in the repo's actions page, where the output will contian a link to the Mayhem run.

## Results
The latest Github workflow can be found [here](https://github.com/bugraonal/markupsafe/actions/runs/5273978708).

The Mayhem run associated with this run can be found [here](https://mayhem.forallsecure.com/bugraonal/markupsafe/escape-fuzzer/23).

According to these results no defects were found. With the code coverage analysis, 5 behaviors were observed. 13,709.64 tests per seconds were performed. The speed went significantly down when the fuzzing flags were use while compiling.

## Challenges faced
The most time I spent on this project is most definitly finding an appropriate project to fuzz. 

When I first started looking for projects, I used the command given in the hackathon resources; this didn't prove very useful as it was hard to understand what these repos did just from their names. After giving up on that front I started to look at some projects I used daily. A lot of them weren't elligible since they were mostly operated with GUIs. 

Only after doing some more reading in the Mayhem documentation I realized I could use libraries/modules by writing a harness, which made my search much easier.

Another problem I faced was trying to interpret the Mayhem errors I was receiving. These were mostly related to the workflow integration; such as the repo not having permission to write to my packages, or Mayhem exitting early from my scripts. 

For troubleshooting these issues, I ended up looking at the documentation. Some of my issues were resolved with the help of the documentation. However, to solve the rest, I had to rely on trial and error; changing how I run my script and then pushing and seeing if it is resolved, then repeat. This took a considerable amount of time I could have spent working on improving my harness.

In hindsight, I should have asked the TA for help for these technical issues.

And lastly, I had trouble figuring out how I would insert the C compiler flags into the Python installation script. I did not realise that the Python package setuptools uses the CFLAGS environmental variable.

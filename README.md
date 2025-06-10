# Controller Required Auth Analyzer

The purpose of this repo is to create a NuGet package which hosts a C# Roslyn Analyzer to call out ASP.NET Core Controllers/Endpoints which do not specify what AuthN/AuthZ is needed. The purpose is to force each controller to specify an Auth attribute, or to force each endpoint in a controller to specify an Auth attribute. This way you know what level of Auth is required by looking directly at the file you are in without having to remember some combination of Global Auth/Controller Level Auth/Endpoint Level Auth.

## Why?

It's for simplicity. Having to keep track of multiple places where auth is defined for an API will eventually lead to a bug where an endpoint doesn't have the correct level of auth. By forcing an Auth attribute in the controller file, we lessen the chance of making that mistake.

And you don't want to make that mistake, because there's enough automated tooling out there (for example: https://github.com/amir-hosseinpour/api-authentication-checker) to test which endpoints don't have authentication required, or just don't require the right amout of authentication.

## How to use this?

It's a Roslyn Analyzer, so all you have to do is add the `ProgrammerAL.Analyzers.ControllerRequiredAuthAnalyzer` NuGet to your `.csproj` file. 

https://www.nuget.org/packages/ProgrammerAL.Analyzers.ControllerRequiredAuthAnalyzer


## What rules does it analyze for?

- PAL3000
  - No Auth attributes were found in the Controller class. Either add an Auth attribute to the Controller itself, or add an attribute to all endpoints.
- PAL3001
  - One or more endpoints were found that do have Auth attributes, but one or more were found without it. Add an Auth attribute to the remaining endpoints.
- PAL3002
  - Both the Controller and one or more endpoints have an auth attribute. Modify the code so the attributes are over the Controller OR the individual endpoints.


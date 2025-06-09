using Gu.Roslyn.Asserts;

using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using ProgrammerAL.Analyzers.ControllerRequiredAuthAnalyzer;

namespace RequiredAuthAnalyzer.Test;

[TestClass]
public class ControllerRequiredAuthAnalyzerAnalyzerTests
{
    private static readonly DiagnosticAnalyzer Analyzer = new ControllerRequiredAuthAnalyzer();
    private static readonly ExpectedDiagnostic MissingAnyAuthDiagnostic = ExpectedDiagnostic.Create(ControllerRequiredAuthAnalyzer.MissingAnyAuthAttributeRule);
    private static readonly ExpectedDiagnostic EndpointMissingAuthDiagnostic = ExpectedDiagnostic.Create(ControllerRequiredAuthAnalyzer.EndpointMissingAuthAttributeRule);
    private static readonly ExpectedDiagnostic ControllerAndEndpointHaveAuthDiagnostic = ExpectedDiagnostic.Create(ControllerRequiredAuthAnalyzer.ControllerAndEndpointHaveAuthAttributeRule);

    [TestMethod]
    public void WhenCodeEmpty_AssertNoDiagnostic()
    {
        //No diagnostics expected to show up
        var code = @"";
        RoslynAssert.Valid(Analyzer, code);
    }

    [TestMethod]
    public void WhenControllerMissingAuthButNoEndpointsExist_AssertNoDiagnostic()
    {
        var code = $$"""
        using Microsoft.AspNetCore.Mvc;

        namespace MyNamespace;

        [ApiController]
        [Route("WeatherForecast")]
        public class WeatherForecastController : ControllerBase
        {
        }
    """;

        RoslynAssert.Valid(Analyzer, code);
    }

    [TestMethod]
    public void WhenControllerAndEndpointMissingAuth_AssertDiagnostic()
    {
        var code = $$"""
        using System.Collections.Generic;
        using Microsoft.AspNetCore.Mvc;
    
        namespace MyNamespace;

        [ApiController]
        [Route("WeatherForecast")]
        public class WeatherForecastController : ControllerBase
        {
            [HttpGet]
            public IEnumerable<int> Get()
            {
                return [1, 2, 3];
            }
        }
    """;

        RoslynAssert.Diagnostics(Analyzer, MissingAnyAuthDiagnostic, code);
    }


    [TestMethod]
    public void WhenSomeEndpointsMissingAuth_AssertDiagnostic()
    {
        var code = $$"""
        using System.Collections.Generic;
        using Microsoft.AspNetCore.Mvc;
        using Microsoft.AspNetCore.Authorization;
    
        namespace MyNamespace;

        [ApiController]
        [Route("WeatherForecast")]
        public class WeatherForecastController : ControllerBase
        {
            [Authorize]
            [HttpGet]
            public IEnumerable<int> Get()
            {
                return [1, 2, 3];
            }

            [HttpGet]
            public IEnumerable<int> Get2()
            {
                return [1, 2, 3];
            }
        }
    """;

        RoslynAssert.Diagnostics(Analyzer, EndpointMissingAuthDiagnostic, code);
    }

    [TestMethod]
    public void WhenControllerAndEndpointHaveAuth_AssertDiagnostic()
    {
        var code = $$"""
        using System.Collections.Generic;
        using Microsoft.AspNetCore.Mvc;
        using Microsoft.AspNetCore.Authorization;
        
        namespace MyNamespace;

        [Authorize]
        [ApiController]
        [Route("WeatherForecast")]
        public class WeatherForecastController : ControllerBase
        {
            [Authorize]
            [HttpGet]
            public IEnumerable<int> Get()
            {
                return [1, 2, 3];
            }
        }
    """;

        RoslynAssert.Diagnostics(Analyzer, ControllerAndEndpointHaveAuthDiagnostic, code);
    }

    [TestMethod]
    [DataRow("Authorize")]
    [DataRow("AuthorizeAttribute")]
    [DataRow("AllowAnonymous")]
    [DataRow("AllowAnonymousAttribute")]
    public void WhenControllerSpecifyingAuthWithShortName_AssertNoDiagnostic(string attributeName)
    {
        var code = $$"""
        using System.Collections.Generic;
        using Microsoft.AspNetCore.Authorization;
        using Microsoft.AspNetCore.Mvc;

        namespace MyNamespace;

        [{{attributeName}}]
        [ApiController]
        [Route("WeatherForecast")]
        public class WeatherForecastController : ControllerBase
        {
            [HttpGet]
            public IEnumerable<int> Get()
            {
                return [1, 2, 3];
            }
        }
    """;

        RoslynAssert.Valid(Analyzer, code);
    }

    [TestMethod]
    [DataRow("Microsoft.AspNetCore.Authorization.Authorize")]
    [DataRow("Microsoft.AspNetCore.Authorization.AuthorizeAttribute")]
    [DataRow("Microsoft.AspNetCore.Authorization.AllowAnonymous")]
    [DataRow("Microsoft.AspNetCore.Authorization.AllowAnonymousAttribute")]
    public void WhenControllerSpecifyingAuthWithFullyQualifiedName_AssertNoDiagnostic(string attributeName)
    {
        var code = $$"""
        using System.Collections.Generic;
        using Microsoft.AspNetCore.Mvc;

        namespace MyNamespace;

        [{{attributeName}}]
        [ApiController]
        [Route("WeatherForecast")]
        public class WeatherForecastController : ControllerBase
        {
            [HttpGet]
            public IEnumerable<int> Get()
            {
                return [1, 2, 3];
            }
        }
    """;

        RoslynAssert.Valid(Analyzer, code);
    }

    [TestMethod]
    [DataRow("Authorize")]
    [DataRow("AuthorizeAttribute")]
    [DataRow("AllowAnonymous")]
    [DataRow("AllowAnonymousAttribute")]
    public void WhenEndpointSpecifyingAuthWithShortName_AssertNoDiagnostic(string attributeName)
    {
        var code = $$"""
        using System.Collections.Generic;
        using Microsoft.AspNetCore.Authorization;
        using Microsoft.AspNetCore.Mvc;

        namespace MyNamespace;

        [ApiController]
        [Route("WeatherForecast")]
        public class WeatherForecastController : ControllerBase
        {
            [{{attributeName}}]
            [HttpGet]
            public IEnumerable<int> Get()
            {
                return [1, 2, 3];
            }
        }
    """;

        RoslynAssert.Valid(Analyzer, code);
    }

    [TestMethod]
    [DataRow("Microsoft.AspNetCore.Authorization.Authorize")]
    [DataRow("Microsoft.AspNetCore.Authorization.AuthorizeAttribute")]
    [DataRow("Microsoft.AspNetCore.Authorization.AllowAnonymous")]
    [DataRow("Microsoft.AspNetCore.Authorization.AllowAnonymousAttribute")]
    public void WhenEndpointSpecifyingAuthWithFullyQualifiedName_AssertNoDiagnostic(string attributeName)
    {
        var code = $$"""
        using System.Collections.Generic;
        using Microsoft.AspNetCore.Mvc;

        namespace MyNamespace;

        [ApiController]
        [Route("WeatherForecast")]
        public class WeatherForecastController : ControllerBase
        {
            [{{attributeName}}]
            [HttpGet]
            public IEnumerable<int> Get()
            {
                return [1, 2, 3];
            }
        }
    """;

        RoslynAssert.Valid(Analyzer, code);
    }

    [TestMethod]
    public void WhenNoAuthAttribute_AssertDiagnostic()
    {
        var code = $$"""
        using System.Collections.Generic;
        using Microsoft.AspNetCore.Mvc;

        namespace MyNamespace;

        [Microsoft.AspNetCore.Mvc.ApiController]
        [Route("[controller]")]
        public class WeatherForecastController : ControllerBase
        {
            [HttpGet(Name = "GetWeatherForecast")]
            public IEnumerable<int> Get()
            {
                return new[]{1, 2, 3};
            }
        }    
        """;

        RoslynAssert.Diagnostics(Analyzer, MissingAnyAuthDiagnostic, code);
    }

    [TestMethod]
    public void WhenControllerSpecifyingAuthWithInheritingAttribute_AssertNoRuleViolation()
    {
        var code = """
        using System.Collections.Generic;
        using Microsoft.AspNetCore.Mvc;
    
        namespace MyNamespace;

        public class MyAuthAttribute : Microsoft.AspNetCore.Authorization.AuthorizeAttribute
        {
        }
        
        [MyAuthAttribute]
        [Microsoft.AspNetCore.Mvc.ApiController]
        [Route("[controller]")]
        public class WeatherForecastController : ControllerBase
        {
            [HttpGet(Name = "GetWeatherForecast")]
            public IEnumerable<int> Get()
            {
                return new[]{1, 2, 3};
            }
        }  
    """;

        RoslynAssert.Valid(Analyzer, code);
    }

    [TestMethod]
    public void WhenEndpointSpecifyingAuthWithInheritingAttribute_AssertNoRuleViolation()
    {
        var code = """
        using System.Collections.Generic;
        using Microsoft.AspNetCore.Mvc;
    
        namespace MyNamespace;

        public class MyAuthAttribute : Microsoft.AspNetCore.Authorization.AuthorizeAttribute
        {
        }
        
        [Microsoft.AspNetCore.Mvc.ApiController]
        [Route("[controller]")]
        public class WeatherForecastController : ControllerBase
        {
            [MyAuthAttribute]
            [HttpGet(Name = "GetWeatherForecast")]
            public IEnumerable<int> Get()
            {
                return new[]{1, 2, 3};
            }
        }  
    """;

        RoslynAssert.Valid(Analyzer, code);
    }
}

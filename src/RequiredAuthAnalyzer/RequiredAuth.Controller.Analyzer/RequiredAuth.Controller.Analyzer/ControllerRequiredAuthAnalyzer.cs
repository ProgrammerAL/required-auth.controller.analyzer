using System;
using System.Collections.Immutable;
using System.Linq;
using System.Xml.Linq;

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

namespace ProgrammerAL.Analyzers.ControllerRequiredAuthAnalyzer;

[DiagnosticAnalyzer(LanguageNames.CSharp)]
public class ControllerRequiredAuthAnalyzer : DiagnosticAnalyzer
{
    private static readonly LocalizableString MissingAnyAuthAttributeTitle = new LocalizableResourceString(nameof(Resources.MissingAnyAuthAttributeTitle), Resources.ResourceManager, typeof(Resources));
    private static readonly LocalizableString MissingAnyAuthAttributeMessageFormat = new LocalizableResourceString(nameof(Resources.MissingAnyAuthAttributeMessageFormat), Resources.ResourceManager, typeof(Resources));
    private static readonly LocalizableString MissingAnyAuthAttributeDescription = new LocalizableResourceString(nameof(Resources.MissingAnyAuthAttributeDescription), Resources.ResourceManager, typeof(Resources));

    private static readonly LocalizableString EndpointMissingAuthAttributeTitle = new LocalizableResourceString(nameof(Resources.EndpointMissingAuthAttributeTitle), Resources.ResourceManager, typeof(Resources));
    private static readonly LocalizableString EndpointMissingAuthAttributeMessageFormat = new LocalizableResourceString(nameof(Resources.EndpointMissingAuthAttributeMessageFormat), Resources.ResourceManager, typeof(Resources));
    private static readonly LocalizableString EndpointMissingAuthAttributeDescription = new LocalizableResourceString(nameof(Resources.EndpointMissingAuthAttributeDescription), Resources.ResourceManager, typeof(Resources));

    private static readonly LocalizableString ControllerAndEndpointHaveAuthAttributeTitle = new LocalizableResourceString(nameof(Resources.ControllerAndEndpointHaveAuthAttributeTitle), Resources.ResourceManager, typeof(Resources));
    private static readonly LocalizableString ControllerAndEndpointHaveAuthAttributeMessageFormat = new LocalizableResourceString(nameof(Resources.ControllerAndEndpointHaveAuthAttributeMessageFormat), Resources.ResourceManager, typeof(Resources));
    private static readonly LocalizableString ControllerAndEndpointHaveAuthAttributeDescription = new LocalizableResourceString(nameof(Resources.ControllerAndEndpointHaveAuthAttributeDescription), Resources.ResourceManager, typeof(Resources));

    public const string Category = "Security";
    public const string MissingAnyAuthAttributeDiagnosticId = "PAL3000";
    public static readonly DiagnosticDescriptor MissingAnyAuthAttributeRule = new DiagnosticDescriptor(MissingAnyAuthAttributeDiagnosticId, MissingAnyAuthAttributeTitle, MissingAnyAuthAttributeMessageFormat, Category, DiagnosticSeverity.Warning, isEnabledByDefault: true, description: MissingAnyAuthAttributeDescription);

    public const string EndpointMissingAuthAttributeDiagnosticId = "PAL3001";
    public static readonly DiagnosticDescriptor EndpointMissingAuthAttributeRule = new DiagnosticDescriptor(EndpointMissingAuthAttributeDiagnosticId, EndpointMissingAuthAttributeTitle, EndpointMissingAuthAttributeMessageFormat, Category, DiagnosticSeverity.Warning, isEnabledByDefault: true, description: EndpointMissingAuthAttributeDescription);

    public const string ControllerAndEndpointHaveAuthAttributeDiagnosticId = "PAL3002";
    public static readonly DiagnosticDescriptor ControllerAndEndpointHaveAuthAttributeRule = new DiagnosticDescriptor(ControllerAndEndpointHaveAuthAttributeDiagnosticId, ControllerAndEndpointHaveAuthAttributeTitle, ControllerAndEndpointHaveAuthAttributeMessageFormat, Category, DiagnosticSeverity.Warning, isEnabledByDefault: true, description: ControllerAndEndpointHaveAuthAttributeDescription);

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => [MissingAnyAuthAttributeRule, EndpointMissingAuthAttributeRule, ControllerAndEndpointHaveAuthAttributeRule];

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();

        context.RegisterSymbolAction(AnalyzeSymbol, SymbolKind.NamedType);
    }

    private static void AnalyzeSymbol(SymbolAnalysisContext context)
    {
        var namedTypeSymbol = context.Symbol as INamedTypeSymbol;
        if (namedTypeSymbol is null)
        {
            return;
        }

        var attributes = namedTypeSymbol.GetAttributes();

        if (IsControllerClass(attributes, context))
        {
            AnalyzeTraditionalControllerEndpoint(namedTypeSymbol, attributes, context);
        }
    }

    private static bool IsControllerClass(ImmutableArray<AttributeData> symbolAttributes, SymbolAnalysisContext context)
    {
        var isController = symbolAttributes
                .Any(x => x.AttributeClass?.ToString() == KnownTypesConstants.ApiControllerAttribute);

        return isController;
    }

    private static void AnalyzeTraditionalControllerEndpoint(INamedTypeSymbol symbol, ImmutableArray<AttributeData> symbolAttributes, SymbolAnalysisContext context)
    {
        //The symantec type is the attribute class's constructor
        //  So use the ContainingType to get the full class name
        var authAttributeSymbol = context.Compilation.GetTypeByMetadataName(KnownTypesConstants.AuthorizeAttribute)
                                    ?? throw new System.Exception($"Could not load C# syntax data for attribute {KnownTypesConstants.AuthorizeAttribute}");
        var anonymousAuthAttributeSymbol = context.Compilation.GetTypeByMetadataName(KnownTypesConstants.AllowAnonymousAttribute)
                                    ?? throw new System.Exception($"Could not load C# syntax data for attribute {KnownTypesConstants.AllowAnonymousAttribute}");

        ImmutableArray<INamedTypeSymbol> knownAuthAttributes = [authAttributeSymbol, anonymousAuthAttributeSymbol];

        var classHasAuthAttribute = ContainsAuthAttribute(symbolAttributes, knownAuthAttributes);
        var publicMethods = LoadPublicMethods(symbol);
        var publicMethodsWithAuthAttribute = LoadPublicMethodsWithAuthAttribute(publicMethods, knownAuthAttributes);

        Analyze(symbol, classHasAuthAttribute, publicMethods, publicMethodsWithAuthAttribute, context);
    }

    private static void Analyze(INamedTypeSymbol controllerSymbol, bool classHasAuthAttribute, ImmutableArray<IMethodSymbol> publicMethods, ImmutableArray<IMethodSymbol> publicMethodsWithAuthAttribute, SymbolAnalysisContext context)
    {
        if (publicMethods.Length <= 0)
        {
            //No endpoints, so don't care about the security attributes
            return;
        }

        var publicMethodsWithoutAuthAttribute = publicMethods.Where(x => !publicMethodsWithAuthAttribute.Contains(x)).ToImmutableArray();

        if (!classHasAuthAttribute)
        {
            if (publicMethods.Length == publicMethodsWithoutAuthAttribute.Length)
            {
                //The class and none of the methods have an auth attribute
                var diagnostic = Diagnostic.Create(MissingAnyAuthAttributeRule, controllerSymbol.Locations[0], controllerSymbol.Name);
                context.ReportDiagnostic(diagnostic);
            }
            else if (publicMethodsWithoutAuthAttribute.Length > 0)
            {
                //Class doesn't have an auth attribute and some public methods don't have an auth method
                // Show diagnostic for each of those methods saying it needs an auth attribute
                foreach (var method in publicMethodsWithoutAuthAttribute)
                {
                    var diagnostic = Diagnostic.Create(EndpointMissingAuthAttributeRule, method.Locations[0], controllerSymbol.Name, method.Name);
                    context.ReportDiagnostic(diagnostic);
                }
            }
        }
        else if (publicMethodsWithAuthAttribute.Length > 0)
        {
            //Class has an auth attribute and some public methods also have one
            // Show diagnostic for each of those methods saying it doesn't need an auth attribute, or to remove attribute from controller
            foreach (var method in publicMethodsWithAuthAttribute)
            {
                var diagnostic = Diagnostic.Create(ControllerAndEndpointHaveAuthAttributeRule, method.Locations[0], controllerSymbol.Name, method.Name);
                context.ReportDiagnostic(diagnostic);
            }
        }
    }

    private static ImmutableArray<IMethodSymbol> LoadPublicMethods(INamedTypeSymbol symbol)
    {
        return symbol.GetMembers()
            .Where(x => x is IMethodSymbol methodSymbol
                        && methodSymbol.DeclaredAccessibility == Accessibility.Public
                        && methodSymbol.IsStatic == false
                        && methodSymbol.MethodKind == MethodKind.Ordinary)
            .Select(x => (IMethodSymbol)x)
            .ToImmutableArray();

    }

    private static bool ContainsAuthAttribute(ImmutableArray<AttributeData> attributes, ImmutableArray<INamedTypeSymbol> authAttributes)
    {
        return attributes
            .Any(x =>
            {
                if (x.AttributeClass is not object)
                {
                    return false;
                }

                return authAttributes.Any(authAttribute => x.AttributeClass.IsOrInheritFrom(authAttribute));
            });
    }

    private static ImmutableArray<IMethodSymbol> LoadPublicMethodsWithAuthAttribute(ImmutableArray<IMethodSymbol> publicMethods, ImmutableArray<INamedTypeSymbol> knownAuthAttributes)
    {
        return publicMethods.Where(method =>
            {
                var attributes = method.GetAttributes();
                return ContainsAuthAttribute(attributes, knownAuthAttributes);
            }
        ).ToImmutableArray();
    }
}

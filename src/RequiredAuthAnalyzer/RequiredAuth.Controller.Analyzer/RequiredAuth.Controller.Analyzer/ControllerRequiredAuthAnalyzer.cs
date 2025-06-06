using System;
using System.Collections.Immutable;
using System.Linq;

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

namespace ProgrammerAL.Analyzers.ControllerRequiredAuthAnalyzer;

[DiagnosticAnalyzer(LanguageNames.CSharp)]
public class ControllerRequiredAuthAnalyzer : DiagnosticAnalyzer
{
    private static readonly LocalizableString Title = new LocalizableResourceString(nameof(Resources.ControllerRequiredAuthAnalyzerTitle), Resources.ResourceManager, typeof(Resources));
    private static readonly LocalizableString MessageFormat = new LocalizableResourceString(nameof(Resources.ControllerRequiredAuthAnalyzerMessageFormat), Resources.ResourceManager, typeof(Resources));
    private static readonly LocalizableString Description = new LocalizableResourceString(nameof(Resources.ControllerRequiredAuthAnalyzerDescription), Resources.ResourceManager, typeof(Resources));

    public const string Category = "Security";
    public const string DiagnosticId = "PAL3000";
    public static readonly DiagnosticDescriptor Rule = new DiagnosticDescriptor(DiagnosticId, Title, MessageFormat, Category, DiagnosticSeverity.Warning, isEnabledByDefault: true, description: Description);

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

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

        Analyze(symbol, classHasAuthAttribute, publicMethods);
    }

    private static void Analyze(INamedTypeSymbol symbol, bool classHasAuthAttribute, ImmutableArray<IMethodSymbol> publicMethods)
    {


        if (!hasAuthAttribute)
        {
            var diagnostic = Diagnostic.Create(Rule, symbol.Locations[0], symbol.Name);
            context.ReportDiagnostic(diagnostic);
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
}

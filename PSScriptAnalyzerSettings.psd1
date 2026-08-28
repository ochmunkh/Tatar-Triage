@{
    # CI gate fails only on Error severity. These rules are intentionally excluded:
    ExcludeRules = @(
        'PSAvoidUsingWriteHost',                          # console UX is intentional
        'PSUseApprovedVerbs',                             # Collect-*/Add-* domain verbs
        'PSUseSingularNouns',
        'PSAvoidUsingPositionalParameters',
        'PSReviewUnusedParameter',
        'PSAvoidGlobalVars',
        'PSUseShouldProcessForStateChangingFunctions',
        'PSAvoidUsingInvokeExpression',
        'PSUseBOMForUnicodeEncodedFile'
    )
}
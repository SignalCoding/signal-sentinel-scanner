using System;

namespace SignalCoding.Annotations
{
    /// <summary>
    /// Explicit, greppable exemption from SC0004. Use ONLY where anonymous access is a designed
    /// behaviour, and always with a justification. Every use is an audit item.
    /// Bootstrap copies this file into the application project.
    /// </summary>
    [AttributeUsage(AttributeTargets.Method | AttributeTargets.Class, AllowMultiple = false)]
    public sealed class AllowAnonymousByDesignAttribute : Attribute
    {
        public string Justification { get; }
        public AllowAnonymousByDesignAttribute(string justification)
        {
            Justification = justification ?? throw new ArgumentNullException(nameof(justification));
        }
    }

    /// <summary>
    /// Explicit, greppable exemption from SC0005. Use ONLY where a non-nullable value-type
    /// [FromForm]/[FromRoute] parameter is safe by design (e.g. the route constraint or an
    /// upstream filter guarantees a parseable value), and always with a justification.
    /// Every use is an audit item. Bootstrap copies this file into the application project.
    /// </summary>
    [AttributeUsage(AttributeTargets.Parameter, AllowMultiple = false)]
    public sealed class BindingValidatedByDesignAttribute : Attribute
    {
        public string Justification { get; }
        public BindingValidatedByDesignAttribute(string justification)
        {
            Justification = justification ?? throw new ArgumentNullException(nameof(justification));
        }
    }
}

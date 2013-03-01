package com.continuuity.internal.test.bytecode;

import com.continuuity.api.annotation.Handle;
import com.continuuity.api.procedure.Procedure;

/**
 *
 */
public final class ProcedureRewriter extends AbstractProcessRewriter {

  public ProcedureRewriter(String applicationId) {
    super(Procedure.class, "handle", Handle.class, applicationId + ".procedure");
  }
}

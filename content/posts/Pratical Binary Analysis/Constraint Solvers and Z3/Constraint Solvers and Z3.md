---
author:
  name: "hexterisk"
date: 2020-01-09
linktitle: Constraint Solvers and Z3
type:
- post
- posts
title: Constraint Solvers and Z3
tags: ["binary", "symbols", "execution", "path", "constraints", "expression"]
weight: 10
categories: ["Practical Binary Analysis"]
---

A constraint solver must be versatile, that is, it should be able to act as an:

*   **Interpreter**: Given the input, solve for the output of the equation.
*   **Inverter**: Given the output, solve for the input of the equation.
*   **Synthesizer**: Act as both Interpreter and Inverter.

## Formulating Programs

Assume a formula _𝑆ₚ(𝑥, 𝑦)_ which holds if and only if program _P(x)_ outputs value _y_ such that

**Program:** f(_𝑥_) { return _𝑥_ + _𝑥_ }

**Formula:** _𝑆𝒻(𝑥, 𝑦) : 𝑦 = 𝑥 + 𝑥_

Now, with the program represented as a formula, the solver can be versatile.

##### Solver as an **Interpreter**:

Given x, evaluate f(x).

𝑆𝒻(𝑥, 𝑦) ∧ 𝑥 = 3

⇨ 𝑦 ↦ 6

##### Solver as an **Inverter**:

Given f(x), find x.

𝑆𝒻(𝑥, 𝑦) ∧ 𝑦 = 6

⇨ 𝑥 ↦ 3

##### This solver “bidirectionality” enables **Synthesis**.

## Specifications

A predicate is a binary-valued function of non-binary variables.

**Precondition** (denoted 𝑝𝑟𝑒(𝑥)) of a procedure _f_ is a predicate over _f_’s parameters 𝑥 that always holds when _f_ is called.  Therefore, _f_ can assume that 𝑝𝑟𝑒(𝑥) holds.

**Postcondition** (denoted 𝑝𝑜𝑠𝑡(𝑥, 𝑦)) is a predicate over parameters of _f_ and its return value 𝑦 that holds when _f_ returns. Therefore, _f_ ensures that 𝑝𝑜𝑠𝑡(𝑥, 𝑦) holds.

These pre- and post-conditions are known as **Contracts**.

Usually, these contracts are tested (that is, evaluated dynamically, during execution).

!["exec"](/Constraint_Solvers_and_Z3/image.png)
__Contracts tested during execution.__

However, with solvers, we want to test these contracts statically, at design time.

!["static"](/Constraint_Solvers_and_Z3/FireShot%20Capture%20210%20-%20%20-%20homes.cs.washington.edu.png)
__Contracts tested during design with solvers.__

## Verification Problem

!["verify"](/Constraint_Solvers_and_Z3/1_FireShot%20Capture%20210%20-%20%20-%20homes.cs.washington.edu.png)
__Verification with Constraint Solver.__

The problem at hand is to basically translate preconditions, postconditions, loop conditions, and assertions into solver's formulae in order to determine/verify if all properties can hold.

**Correctness condition** _𝜙_ says that the program is correct for all valid inputs:

∀𝑥 . 𝑝𝑟𝑒(𝑥) ⇒ 𝑆ₚ(𝑥, 𝑦) ∧ 𝑝𝑜𝑠𝑡(𝑥, 𝑦)

where, 𝑝𝑟𝑒(𝑥) is valid for all 𝑥_._

            𝑆ₚ(𝑥, 𝑦) computes 𝑦 from 𝑥_._

 𝑝𝑜𝑠𝑡(𝑥, 𝑦) is correct.

To prove correctness for all inputs _𝑥_, search for counterexample 𝑥 where 𝜙 does not hold:

¬ (∀𝑥 . 𝑝𝑟𝑒(𝑥) ⇒ 𝑆ₚ(𝑥, 𝑦) ∧ 𝑝𝑜𝑠𝑡(𝑥, 𝑦))

⇨ ∃𝑥 . ¬ 𝑝𝑟𝑒(𝑥) ⇒ 𝑆ₚ(𝑥, 𝑦) ∧ 𝑝𝑜𝑠𝑡(𝑥, 𝑦)

⇨ ∃𝑥 . 𝑝𝑟𝑒(𝑥) ∧ ¬ 𝑆ₚ(𝑥, 𝑦) ∧ 𝑝𝑜𝑠𝑡(𝑥, 𝑦)

Since 𝑆ₚ always holds, as we can always find 𝑦 given 𝑥,

⇨ ∃𝑥 . 𝑝𝑟𝑒(𝑥) ∧ 𝑆ₚ(𝑥, 𝑦) ∧ ¬ 𝑝𝑜𝑠𝑡(𝑥, 𝑦)

!["predicate"](/Constraint_Solvers_and_Z3/2_FireShot%20Capture%20210%20-%20%20-%20homes.cs.washington.edu.png)
__Passing the verification condition to the solver.__

## SAT Solver

A formula/constraint _F_ is satisfiable if there is some assignment of appropriate values to its uninterpreted symbols under which _F_ evaluates to true. Thus, the language of SAT Solvers is Boolean logic.

A **Satisfiability Solver** accepts a formula _𝜙(𝑥, 𝑦, 𝑧)_ and checks if _𝜙_ is satisfiable (SAT).

If yes, the solver returns a model _m_, a valuation of _𝑥, 𝑦, 𝑧_ that satisfies _𝜙_, ie, _𝑚_ makes _𝜙_ true. If the formula is unsatisfiable (UNSAT), some solvers return minimal unsat core of _𝜙_, a smallest set of clauses of _𝜙_ that cannot be satisfied.

Such problems are typically in the CNF(Conjuctive Normal Form) form, that is, a conjunction of one or more clauses, where a clause is a disjunction of literals (an AND of ORs).

SAT solvers are automatic and efficient. As a result, they are frequently used as the “engine” behind verification applications.

## SMT Solver

The **Satisfiability Modulo Theories** problem is a decision problem for logical formulas with respect to combinations of background theories expressed in classical first-order logic with equality.

SAT Solvers' basic functionality depends on Boolean logic. Systems are usually designed and modeled at a higher level than the Boolean level and the translation to Boolean logic can be expensive. SMT Solvers therefore aim to create verification engines that can reason natively at a higher level of abstraction while retaining the efficiency of SAT Solvers. The language of SMT Solvers is therefore First-Order-Logic. The language includes the Boolean operations of Boolean logic, but instead of propositional variables, more complicated expressions involving constant, function, and predicate symbols are used. In other words, imagine an instance of the Boolean satisfiability problem (SAT) in which some of the binary variables are replaced by predicates over a suitable set of non-binary variables.

A very popular SMT Solver is Z3.

## Z3

Introducing the powers of [Z3](https://github.com/Z3Prover/z3/wiki#background) in python, run `pip install z3-solver` to install it via pip.

Follow [archived docs](https://hexterisk.github.io/Z3Py-Archive/guide-examples.htm) for basic syntax and a jump start.

[Official Docs](https://z3prover.github.io/api/html/)for referencing the API in different languages.

Taking Z3 for a spin, let's tackle a well-known problem: Sudoku Solver.

Read this [page](https://hexterisk.tech/Z3Py-Archive/Sudoku%20solver%20using%20Z3.html) implemented in this [IPython Notebook](https://github.com/hexterisk/Z3Py-Archive/blob/master/Sudoku%20solver%20using%20Z3.ipynb) for a comprehensive explanation on a Sudoku Solver.

Using Z3 for binary analysis, let's analyse a binary.

Taking up a serial validator, let's take a look at the binary's decompilation.

We are looking at the decompilation to save ourselves the time and effort of reverse engineering, since the main focus is to demonstrate the usage of Z3 to resolve a serial check.

!["main"](/Constraint_Solvers_and_Z3/2020-05-27-145823_1920x1080_scrot.png)
_main function._

!["validate"](/Constraint_Solvers_and_Z3/2020-05-27-150139_1920x1080_scrot.png)
_validate\_serial function._

Examining the `validate_serial` function, it is clear that

*   Serial is passed in `a1`.
*   Length of the serial is 13, passed in `a2`.
*   `v5` is the iterator for the loop run on `a1`. Loop runs till the last element, but not on last element since it's an exit controlled loop using a pre-increment operator.
*   All values in `a1` should be between 46 and 57(line 14), which then has 48 subtracted from it(line 16). Even out to values between 0 and 9(both inclusive).
*   `v4` is a running sum, with an initial value of 3. Only uses previous value and serial digit value to update current value.
*   Returns boolean value, so the target is to get the output as `Valid: 1`.

Using the constraints and computations specified, we'll write a Z3 script to give us our good serial.

Read this [page](https://hexterisk.tech/Z3Py-Archive/Serial%20solver%20using%20Z3.html) implemented in this [IPython Notebook](https://github.com/hexterisk/Z3Py-Archive/blob/master/Serial%20solver%20using%20Z3.ipynb) to follow the solution for this problem.

!["solution"](/Constraint_Solvers_and_Z3/2020-05-27-182912_1920x1080_scrot.png)
_Output._

Credits for the guidance to Calle Svensson's talk "SMT in reverse engineering, for dummies" at SEC-T 0x09.

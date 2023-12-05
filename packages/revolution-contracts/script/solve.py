from sympy import symbols, Eq, solve, log, simplify, pretty

# Define the symbols
p0, r, k, t, x_start, y = symbols('p0 r k t xstart y', real=True, positive=True)
x_bought = symbols('x_bought', real=True)

# Define the equation
# y = (p0 * r / log(1 - k)) * ((1 - k)**(t - x_start / r) - (1 - k)**(t - (x_start + x_bought) / r))
equation = Eq(y, (p0 * r / log(1 - k)) * ((1 - k)**(t - x_start / r) - (1 - k)**(t - (x_start + x_bought) / r)))

# Solve the equation for x_bought
solution = solve(equation, x_bought)

print(pretty(solution))

# Display the simplified solution
print(simplify(solution[0]))

//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
//

#ifndef __INET_MATH_FUNCTIONS_H_
#define __INET_MATH_FUNCTIONS_H_

#include <algorithm>
#include "inet/common/math/IFunction.h"
#include "inet/common/math/Interpolators.h"

namespace inet {

namespace math {

using namespace inet::units::values;

template<typename R, typename D>
class INET_API FunctionChecker
{
  protected:
    const Ptr<const IFunction<R, D>> f;

  public:
    FunctionChecker(const Ptr<const IFunction<R, D>>& f) : f(f) { }

    void check() const {
        f->partition(f->getDomain(), [&] (const typename D::I& i, const IFunction<R, D> *g) {
            auto check = std::function<void (const typename D::P&)>([&] (const typename D::P& p) {
                if (i.contains(p)) {
                    R rF = f->getValue(p);
                    R rG = g->getValue(p);
                    ASSERT(rF == rG || (std::isnan(toDouble(rF)) && std::isnan(toDouble(rG))));
                }
            });
            iterateBoundaries(i, check);
            check((i.getLower() + i.getUpper()) / 2);
        });
    }
};

template<typename R, typename D>
class INET_API DomainLimitedFunction;

template<typename R, typename D>
class INET_API AdditionFunction;

template<typename R, typename D>
class INET_API SubtractionFunction;

template<typename R, typename D>
class INET_API MultiplicationFunction;

template<typename R, typename D>
class INET_API DivisionFunction;

template<typename R, typename D, int DIMS, typename RI, typename DI>
class INET_API IntegratedFunction;

template<typename R, typename D, int DIMENSION, typename X>
class INET_API ApproximatedFunction;

template<typename R, typename D>
class INET_API FunctionBase : public IFunction<R, D>
{
  public:
    virtual Interval<R> getRange() const override {
        return Interval<R>(getLowerBoundary<R>(), getUpperBoundary<R>(), 0b1);
    }

    virtual typename D::I getDomain() const override {
        return typename D::I(D::P::getLowerBoundaries(), D::P::getUpperBoundaries(), (1 << std::tuple_size<typename D::P::type>::value) - 1);
    }

    virtual bool isFinite() const override { return isFinite(getDomain()); }
    virtual bool isFinite(const typename D::I& i) const override {
        bool result = true;
        this->partition(i, [&] (const typename D::I& i1, const IFunction<R, D> *f) {
            result &= f->isFinite(i1);
        });
        return result;
    }

    virtual R getMin() const override { return getMin(getDomain()); }
    virtual R getMin(const typename D::I& i) const override {
        R result(getUpperBoundary<R>());
        this->partition(i, [&] (const typename D::I& i1, const IFunction<R, D> *f) {
            result = std::min(f->getMin(i1), result);
        });
        return result;
    }

    virtual R getMax() const override { return getMax(getDomain()); }
    virtual R getMax(const typename D::I& i) const override {
        R result(getLowerBoundary<R>());
        this->partition(i, [&] (const typename D::I& i1, const IFunction<R, D> *f) {
            result = std::max(f->getMax(i1), result);
        });
        return result;
    }

    virtual R getMean() const override { return getMean(getDomain()); }
    virtual R getMean(const typename D::I& i) const override {
        return getIntegral(i) / i.getVolume();
    }

    virtual R getIntegral() const override { return getIntegral(getDomain()); }
    virtual R getIntegral(const typename D::I& i) const override {
        R result(0);
        this->partition(i, [&] (const typename D::I& i1, const IFunction<R, D> *f) {
            double volume = i1.getVolume();
            R value = f->getMean(i1);
            if (!(value == R(0) && std::isinf(volume)))
                result += volume * value;
        });
        return result;
    }

    virtual const Ptr<const IFunction<R, D>> add(const Ptr<const IFunction<R, D>>& o) const override {
        return makeShared<AdditionFunction<R, D>>(const_cast<FunctionBase<R, D> *>(this)->shared_from_this(), o);
    }

    virtual const Ptr<const IFunction<R, D>> subtract(const Ptr<const IFunction<R, D>>& o) const override {
        return makeShared<SubtractionFunction<R, D>>(const_cast<FunctionBase<R, D> *>(this)->shared_from_this(), o);
    }

    virtual const Ptr<const IFunction<R, D>> multiply(const Ptr<const IFunction<double, D>>& o) const override {
        return makeShared<MultiplicationFunction<R, D>>(const_cast<FunctionBase<R, D> *>(this)->shared_from_this(), o);
    }

    virtual const Ptr<const IFunction<double, D>> divide(const Ptr<const IFunction<R, D>>& o) const override {
        return makeShared<DivisionFunction<R, D>>(const_cast<FunctionBase<R, D> *>(this)->shared_from_this(), o);
    }

    virtual void print(std::ostream& os) const override {
        os << "function" << D() << " -> ";
        outputUnit(os, R());
        os << " {" << std::endl;
        this->partition(getDomain(), [&] (const typename D::I& i, const IFunction<R, D> *g) {
            os << "  ";
            g->print(os, i);
        });
        os << "} min = " << getMin() << ", max = " << getMax() << ", mean = " << getMean();
    }

    virtual void print(std::ostream& os, const typename D::I& i) const override {
        os << "over " << i << " -> { ";
        iterateBoundaries(i, std::function<void (const typename D::P&)>([&] (const typename D::P& p) {
            os << "@" << p << " = " << this->getValue(p) << ", ";
        }));
        os << "min = " << getMin(i) << ", max = " << getMax(i) << ", mean = " << getMean(i) << " }" << std::endl;
    }
};

template<typename R, typename D, int DIMS, typename RI, typename DI>
Ptr<const IFunction<RI, DI>> integrate(const Ptr<const IFunction<R, D>>& f) {
    return makeShared<IntegratedFunction<R, D, DIMS, RI, DI>>(f);
}

template<typename R, typename D>
class INET_API DomainLimitedFunction : public FunctionBase<R, D>
{
  protected:
    const Ptr<const IFunction<R, D>> f;
    const Interval<R> range;
    const typename D::I domain;

  public:
    DomainLimitedFunction(const Ptr<const IFunction<R, D>>& f, const typename D::I& domain) : f(f), range(Interval<R>(f->getMin(domain), f->getMax(domain), 0b1)), domain(domain) { }

    virtual Interval<R> getRange() const override { return range; };
    virtual typename D::I getDomain() const override { return domain; };

    virtual R getValue(const typename D::P& p) const override {
        ASSERT(domain.contains(p));
        return f->getValue(p);
    }

    virtual void partition(const typename D::I& i, const std::function<void (const typename D::I&, const IFunction<R, D> *)> g) const override {
        const auto& i1 = i.intersect(domain);
        if (!i1.isEmpty())
            f->partition(i1, g);
    }

    virtual R getMin(const typename D::I& i) const override {
        return f->getMin(i.intersect(domain));
    }

    virtual R getMax(const typename D::I& i) const override {
        return f->getMax(i.intersect(domain));
    }

    virtual R getMean(const typename D::I& i) const override {
        return f->getMean(i.intersect(domain));
    }

    virtual R getIntegral(const typename D::I& i) const override {
        return f->getIntegral(i.intersect(domain));
    }
};

template<typename R, typename D>
Ptr<const DomainLimitedFunction<R, D>> makeFirstQuadrantLimitedFunction(const Ptr<const IFunction<R, D>>& f) {
    typename D::I i(D::P::getZero(), D::P::getUpperBoundaries(), (1 << std::tuple_size<typename D::P::type>::value) - 1);
    return makeShared<DomainLimitedFunction<R, D>>(f, i);
}

template<typename R, typename D>
class INET_API ConstantFunction : public FunctionBase<R, D>
{
  protected:
    const R r;

  public:
    ConstantFunction(R r) : r(r) { }

    virtual R getConstantValue() const { return r; }

    virtual Interval<R> getRange() const override { return Interval<R>(r, r, 0b1); }

    virtual R getValue(const typename D::P& p) const override { return r; }

    virtual void partition(const typename D::I& i, const std::function<void (const typename D::I&, const IFunction<R, D> *)> f) const override {
        f(i, this);
    }

    virtual bool isFinite(const typename D::I& i) const override { return std::isfinite(toDouble(r)); }
    virtual R getMin(const typename D::I& i) const override { return r; }
    virtual R getMax(const typename D::I& i) const override { return r; }
    virtual R getMean(const typename D::I& i) const override { return r; }
    virtual R getIntegral(const typename D::I& i) const override { return r == R(0) ? r : r * i.getVolume(); }

    virtual void print(std::ostream& os, const typename D::I& i) const override {
        os << "constant over " << i << " -> " << r << std::endl;
    }
};

template<typename R, typename X>
class INET_API OneDimensionalBoxcarFunction : public FunctionBase<R, Domain<X>>
{
  protected:
    const X lower;
    const X upper;
    const R r;

  public:
    OneDimensionalBoxcarFunction(X lower, X upper, R r) : lower(lower), upper(upper), r(r) {
        ASSERT(r > R(0));
    }

    virtual Interval<R> getRange() const override { return Interval<R>(R(0), r, 0b1); }

    virtual R getValue(const Point<X>& p) const override {
        return std::get<0>(p) < lower || std::get<0>(p) >= upper ? R(0) : r;
    }

    virtual void partition(const Interval<X>& i, const std::function<void (const Interval<X>&, const IFunction<R, Domain<X>> *)> f) const override {
        const auto& i1 = i.intersect(Interval<X>(getLowerBoundary<X>(), Point<X>(lower), 0));
        if (!i1.isEmpty()) {
            ConstantFunction<R, Domain<X>> g(R(0));
            f(i1, &g);
        }
        const auto& i2 = i.intersect(Interval<X>(Point<X>(lower), Point<X>(upper), 0));
        if (!i2.isEmpty()) {
            ConstantFunction<R, Domain<X>> g(r);
            f(i2, &g);
        }
        const auto& i3 = i.intersect(Interval<X>(Point<X>(upper), getUpperBoundary<X>(), 0b1));
        if (!i3.isEmpty()) {
            ConstantFunction<R, Domain<X>> g(R(0));
            f(i3, &g);
        }
    }

    virtual bool isFinite(const Interval<X>& i) const override { return std::isfinite(toDouble(r)); }
};

template<typename R, typename X, typename Y>
class INET_API TwoDimensionalBoxcarFunction : public FunctionBase<R, Domain<X, Y>>
{
  protected:
    const X lowerX;
    const X upperX;
    const Y lowerY;
    const Y upperY;
    const R r;

  protected:
    void callf(const Interval<X, Y>& i, const std::function<void (const Interval<X, Y>&, const IFunction<R, Domain<X, Y>> *)> f, R r) const {
        if (!i.isEmpty()) {
            ConstantFunction<R, Domain<X, Y>> g(r);
            f(i, &g);
        }
    }

  public:
    TwoDimensionalBoxcarFunction(X lowerX, X upperX, Y lowerY, Y upperY, R r) : lowerX(lowerX), upperX(upperX), lowerY(lowerY), upperY(upperY), r(r) {
        ASSERT(r > R(0));
    }

    virtual Interval<R> getRange() const override { return Interval<R>(R(0), r, 0b1); }

    virtual R getValue(const Point<X, Y>& p) const override {
        return std::get<0>(p) < lowerX || std::get<0>(p) >= upperX || std::get<1>(p) < lowerY || std::get<1>(p) >= upperY ? R(0) : r;
    }

    virtual void partition(const Interval<X, Y>& i, const std::function<void (const Interval<X, Y>&, const IFunction<R, Domain<X, Y>> *)> f) const override {
        callf(i.intersect(Interval<X, Y>(Point<X, Y>(getLowerBoundary<X>(), getLowerBoundary<Y>()), Point<X, Y>(X(lowerX), Y(lowerY)), 0)), f, R(0));
        callf(i.intersect(Interval<X, Y>(Point<X, Y>(X(lowerX), getLowerBoundary<Y>()), Point<X, Y>(X(upperX), Y(lowerY)), 0)), f, R(0));
        callf(i.intersect(Interval<X, Y>(Point<X, Y>(X(upperX), getLowerBoundary<Y>()), Point<X, Y>(getUpperBoundary<X>(), Y(lowerY)), 0b10)), f, R(0));

        callf(i.intersect(Interval<X, Y>(Point<X, Y>(getLowerBoundary<X>(), Y(lowerY)), Point<X, Y>(X(lowerX), Y(upperY)), 0)), f, R(0));
        callf(i.intersect(Interval<X, Y>(Point<X, Y>(X(lowerX), Y(lowerY)), Point<X, Y>(X(upperX), Y(upperY)), 0)), f, r);
        callf(i.intersect(Interval<X, Y>(Point<X, Y>(X(upperX), Y(lowerY)), Point<X, Y>(getUpperBoundary<X>(), Y(upperY)), 0b10)), f, R(0));

        callf(i.intersect(Interval<X, Y>(Point<X, Y>(getLowerBoundary<X>(), Y(upperY)), Point<X, Y>(X(lowerX), getUpperBoundary<Y>()), 0b01)), f, R(0));
        callf(i.intersect(Interval<X, Y>(Point<X, Y>(X(lowerX), Y(upperY)), Point<X, Y>(X(upperX), getUpperBoundary<Y>()), 0b01)), f, R(0));
        callf(i.intersect(Interval<X, Y>(Point<X, Y>(X(upperX), Y(upperY)), Point<X, Y>(getUpperBoundary<X>(), getUpperBoundary<Y>()), 0b11)), f, R(0));
    }

    virtual bool isFinite(const Interval<X, Y>& i) const override { return std::isfinite(toDouble(r)); }
};

template<typename R, typename D>
class INET_API LinearInterpolatedFunction : public FunctionBase<R, D>
{
  protected:
    const typename D::P lower; // value is ignored in all but one dimension
    const typename D::P upper; // value is ignored in all but one dimension
    const R rLower;
    const R rUpper;
    const int dimension;

  public:
    LinearInterpolatedFunction(typename D::P lower, typename D::P upper, R rLower, R rUpper, int dimension) : lower(lower), upper(upper), rLower(rLower), rUpper(rUpper), dimension(dimension) { }

    virtual const typename D::P& getLower() const { return lower; }
    virtual const typename D::P& getUpper() const { return upper; }
    virtual R getRLower() const { return rLower; }
    virtual R getRUpper() const { return rUpper; }
    virtual int getDimension() const { return dimension; }

    virtual double getA() const { return toDouble(rUpper - rLower) / toDouble(upper.get(dimension) - lower.get(dimension)); }
    virtual double getB() const { return (toDouble(rLower) * upper.get(dimension) - toDouble(rUpper) * lower.get(dimension)) / (upper.get(dimension) - lower.get(dimension)); }

    virtual Interval<R> getRange() const override { return Interval<R>(std::min(rLower, rUpper), std::max(rLower, rUpper), 0b1); }
    virtual typename D::I getDomain() const override { return typename D::I(lower, upper, 0); };

    virtual R getValue(const typename D::P& p) const override {
        double alpha = (p - lower).get(dimension) / (upper - lower).get(dimension);
        return rLower * (1 - alpha) + rUpper * alpha;
    }

    virtual void partition(const typename D::I& i, const std::function<void (const typename D::I&, const IFunction<R, D> *)> f) const override {
        f(i, this);
    }

    virtual bool isFinite(const typename D::I& i) const override {
        return std::isfinite(toDouble(rLower)) && std::isfinite(toDouble(rUpper));
    }

    virtual R getMin(const typename D::I& i) const override {
        return std::min(getValue(i.getLower()), getValue(i.getUpper()));
    }

    virtual R getMax(const typename D::I& i) const override {
        return std::max(getValue(i.getLower()), getValue(i.getUpper()));
    }

    virtual R getMean(const typename D::I& i) const override {
        return getValue((i.getLower() + i.getUpper()) / 2);
    }

    virtual void print(std::ostream& os, const typename D::I& i) const override {
        os << "linear over " << i << " -> from " << getValue(i.getLower()) << " to " << getValue(i.getUpper()) << std::endl;
    }
};

template<typename R, typename D>
class INET_API BilinearInterpolatedFunction : public FunctionBase<R, D>
{
  protected:
    const typename D::P lowerLower; // value is ignored in all but two dimensions
    const typename D::P lowerUpper; // value is ignored in all but two dimensions
    const typename D::P upperLower; // value is ignored in all but two dimensions
    const typename D::P upperUpper; // value is ignored in all but two dimensions
    const R rLowerLower;
    const R rLowerUpper;
    const R rUpperLower;
    const R rUpperUpper;
    const int dimension1;
    const int dimension2;

  protected:
    typename D::I getOtherInterval(const typename D::I& i) const {
        const typename D::P& lower = i.getLower();
        const typename D::P& upper = i.getUpper();
        typename D::P lowerUpper = D::P::getZero();
        typename D::P upperLower = D::P::getZero();
        lowerUpper.set(dimension1, lower.get(dimension1));
        lowerUpper.set(dimension2, upper.get(dimension2));
        upperLower.set(dimension1, upper.get(dimension1));
        upperLower.set(dimension2, lower.get(dimension2));
        return typename D::I(lowerUpper, upperLower, i.getClosed());
    }

  public:
    BilinearInterpolatedFunction(const typename D::P& lowerLower, const typename D::P& lowerUpper, const typename D::P& upperLower, const typename D::P& upperUpper,
                                 const R rLowerLower, const R rLowerUpper, const R rUpperLower, const R rUpperUpper, const int dimension1, const int dimension2) :
        lowerLower(lowerLower), lowerUpper(lowerUpper), upperLower(upperLower), upperUpper(upperUpper),
        rLowerLower(rLowerLower), rLowerUpper(rLowerUpper), rUpperLower(rUpperLower), rUpperUpper(rUpperUpper),
        dimension1(dimension1), dimension2(dimension2) { }

    virtual const typename D::P& getLowerLower() const { return lowerLower; }
    virtual const typename D::P& getLowerUpper() const { return lowerUpper; }
    virtual const typename D::P& getUpperLower() const { return upperLower; }
    virtual const typename D::P& getUpperUpper() const { return upperUpper; }
    virtual R getRLowerLower() const { return rLowerLower; }
    virtual R getRLowerUpper() const { return rLowerUpper; }
    virtual R getRUpperLower() const { return rUpperLower; }
    virtual R getRUpperUpper() const { return rUpperUpper; }
    virtual int getDimension1() const { return dimension1; }
    virtual int getDimension2() const { return dimension2; }

    virtual Interval<R> getRange() const override { return Interval<R>(std::min(std::min(rLowerLower, rLowerUpper), std::min(rUpperLower, rUpperUpper)),
                                                                       std::max(std::max(rLowerLower, rLowerUpper), std::max(rUpperLower, rUpperUpper)), 0b1); }
    virtual typename D::I getDomain() const override { throw cRuntimeError("TODO"); };

    virtual R getValue(const typename D::P& p) const override {
        double lowerAlpha = (p - lowerLower).get(dimension1) / (upperLower - lowerLower).get(dimension1);
        R rLower = rLowerLower * (1 - lowerAlpha) + rUpperLower * lowerAlpha;
        const typename D::P lower = lowerLower * (1 - lowerAlpha) + upperLower * lowerAlpha;

        double upperAlpha = (p - lowerUpper).get(dimension1) / (upperUpper - lowerUpper).get(dimension1);
        R rUpper = rLowerUpper * (1 - upperAlpha) + rUpperUpper * upperAlpha;
        const typename D::P upper = lowerUpper * (1 - upperAlpha) + upperUpper * upperAlpha;

        double alpha = (p - lower).get(dimension2) / (upper - lower).get(dimension2);
        return rLower * (1 - alpha) + rUpper * alpha;
    }

    virtual void partition(const typename D::I& i, const std::function<void (const typename D::I&, const IFunction<R, D> *)> f) const override {
        f(i, this);
    }

    virtual R getMin(const typename D::I& i) const override {
        auto j = getOtherInterval(i);
        return std::min(std::min(getValue(i.getLower()), getValue(j.getLower())), std::min(getValue(j.getUpper()), getValue(i.getUpper())));
    }

    virtual R getMax(const typename D::I& i) const override {
        auto j = getOtherInterval(i);
        return std::max(std::max(getValue(i.getLower()), getValue(j.getLower())), std::max(getValue(j.getUpper()), getValue(i.getUpper())));
    }

    virtual R getMean(const typename D::I& i) const override {
        return getValue((i.getLower() + i.getUpper()) / 2);
    }
};

template<typename R, typename X>
class INET_API OneDimensionalInterpolatedFunction : public FunctionBase<R, Domain<X>>
{
  protected:
    const std::map<X, std::pair<R, const IInterpolator<X, R> *>> rs;

  public:
    OneDimensionalInterpolatedFunction(const std::map<X, R>& rs, const IInterpolator<X, R> *interpolator) : rs([&] () {
        std::map<X, std::pair<R, const IInterpolator<X, R> *>> result;
        for (auto it : rs)
            result[it.first] = {it.second, interpolator};
        return result;
    } ()) { }

    OneDimensionalInterpolatedFunction(const std::map<X, std::pair<R, const IInterpolator<X, R> *>>& rs) : rs(rs) { }

    virtual R getValue(const Point<X>& p) const override {
        X x = std::get<0>(p);
        auto it = rs.equal_range(x);
        auto& lt = it.first;
        auto& ut = it.second;
        // TODO: this nested if looks horrible
        if (lt != rs.end() && lt->first == x) {
            if (ut == rs.end())
                return lt->second.first;
            else {
                const auto interpolator = lt->second.second;
                return interpolator->getValue(lt->first, lt->second.first, ut->first, ut->second.first, x);
            }
        }
        else {
            ASSERT(lt != rs.end() && ut != rs.end());
            lt--;
            const auto interpolator = lt->second.second;
            return interpolator->getValue(lt->first, lt->second.first, ut->first, ut->second.first, x);
        }
    }

    virtual void partition(const Interval<X>& i, const std::function<void (const Interval<X>&, const IFunction<R, Domain<X>> *)> f) const override {
        // loop from less or equal than lower to greater or equal than upper inclusive both ends
        auto lt = rs.lower_bound(std::get<0>(i.getLower()));
        auto ut = rs.upper_bound(std::get<0>(i.getUpper()));
        if (lt->first > std::get<0>(i.getLower()))
            lt--;
        if (ut == rs.end())
            ut--;
        for (auto it = lt; it != ut; it++) {
            auto jt = it;
            jt++;
            auto kt = jt;
            kt++;
            auto i1 = i.intersect(Interval<X>(Point<X>(it->first), Point<X>(jt->first), kt == rs.end() ? 0b1 : 0b0));
            if (!i1.isEmpty()) {
                const auto interpolator = it->second.second;
                if (dynamic_cast<const EitherInterpolator<X, R> *>(interpolator)) {
                    ConstantFunction<R, Domain<X>> g(it->second.first);
                    f(i1, &g);
                }
                else if (dynamic_cast<const LeftInterpolator<X, R> *>(interpolator)) {
                    ConstantFunction<R, Domain<X>> g(it->second.first); // TODO: what about the ends?
                    f(i1, &g);
                }
                else if (dynamic_cast<const RightInterpolator<X, R> *>(interpolator)) {
                    ConstantFunction<R, Domain<X>> g(jt->second.first); // TODO: what about the ends?
                    f(i1, &g);
                }
                else if (dynamic_cast<const LinearInterpolator<X, R> *>(interpolator)) {
                    LinearInterpolatedFunction<R, Domain<X>> g(Point<X>(it->first), Point<X>(jt->first), it->second.first, jt->second.first, 0);
                    simplifyAndCall(i1, &g, f);
                }
                else
                    throw cRuntimeError("TODO");
            }
        }
    }

    virtual bool isFinite(const Interval<X>& i) const override { return true; }
};

//template<typename R, typename X, typename Y>
//class INET_API TwoDimensionalInterpolatedFunction : public Function<R, X, Y>
//{
//  protected:
//    const IInterpolator<T, R>& xi;
//    const IInterpolator<T, R>& yi;
//    const std::vector<std::tuple<X, Y, R>> rs;
//
//  public:
//    TwoDimensionalInterpolatedFunction(const IInterpolator<T, R>& xi, const IInterpolator<T, R>& yi, const std::vector<std::tuple<X, Y, R>>& rs) :
//        xi(xi), yi(yi), rs(rs) { }
//
//    virtual R getValue(const Point<T>& p) const override {
//        throw cRuntimeError("TODO");
//    }
//
//    virtual void partition(const Interval<X, Y>& i, const std::function<void (const Interval<X, Y>&, const IFunction<R, Domain<X, Y>> *)> f) const override {
//        throw cRuntimeError("TODO");
//    }
//};

//template<typename R, typename D0, typename D>
//class INET_API FunctionInterpolatingFunction : public Function<R, D>
//{
//  protected:
//    const IInterpolator<R, D0>& i;
//    const std::map<D0, const IFunction<R, D> *> fs;
//
//  public:
//    FunctionInterpolatingFunction(const IInterpolator<R, D0>& i, const std::map<D0, const IFunction<R, D> *>& fs) : i(i), fs(fs) { }
//
//    virtual R getValue(const Point<D0, D>& p) const override {
//        D0 x = std::get<0>(p);
//        auto lt = fs.lower_bound(x);
//        auto ut = fs.upper_bound(x);
//        ASSERT(lt != fs.end() && ut != fs.end());
//        typename D::P q;
//        return i.get(lt->first, lt->second->getValue(q), ut->first, ut->second->getValue(q), x);
//    }
//
//    virtual void partition(const Interval<D0, D>& i, const std::function<void (const Interval<D0, D>&, const IFunction<R, D> *)> f) const override {
//        throw cRuntimeError("TODO");
//    }
//};

//template<typename R, typename D>
//class INET_API GaussFunction : public Function<R, D>
//{
//  protected:
//    const R mean;
//    const R stddev;
//
//  public:
//    GaussFunction(R mean, R stddev) : mean(mean), stddev(stddev) { }
//
//    virtual R getValue(const typename D::P& p) const override {
//        throw cRuntimeError("TODO");
//    }
//
//    virtual void partition(const typename D::I& i, const std::function<void (const typename D::I&, const IFunction<R, D> *)> f) const override {
//        throw cRuntimeError("TODO");
//    }
//};

template<typename R, typename X, typename Y>
class INET_API OrthogonalCombinatorFunction : public FunctionBase<R, Domain<X, Y>>
{
  protected:
    const Ptr<const IFunction<R, Domain<X>>> f;
    const Ptr<const IFunction<double, Domain<Y>>> g;

  public:
    OrthogonalCombinatorFunction(const Ptr<const IFunction<R, Domain<X>>>& f, const Ptr<const IFunction<double, Domain<Y>>>& g) : f(f), g(g) { }

    virtual R getValue(const Point<X, Y>& p) const override {
        return f->getValue(std::get<0>(p)) * g->getValue(std::get<1>(p));
    }

    virtual void partition(const Interval<X, Y>& i, const std::function<void (const Interval<X, Y>&, const IFunction<R, Domain<X, Y>> *)> h) const override {
        Interval<X> ix(Point<X>(std::get<0>(i.getLower())), Point<X>(std::get<0>(i.getUpper())), (i.getClosed() & 0b10) >> 1);
        Interval<Y> iy(Point<Y>(std::get<1>(i.getLower())), Point<Y>(std::get<1>(i.getUpper())), (i.getClosed() & 0b01) >> 0);
        f->partition(ix, [&] (const Interval<X>& ixf, const IFunction<R, Domain<X>> *if1) {
            g->partition(iy, [&] (const Interval<Y>& iyg, const IFunction<double, Domain<Y>> *if2) {
                Point<X, Y> lower(std::get<0>(ixf.getLower()), std::get<0>(iyg.getLower()));
                Point<X, Y> upper(std::get<0>(ixf.getUpper()), std::get<0>(iyg.getUpper()));
                unsigned int closed = (ixf.getClosed() << 1) | (iyg.getClosed() << 0);
                if (auto cif1 = dynamic_cast<const ConstantFunction<R, Domain<X>> *>(if1)) {
                    if (auto cif2 = dynamic_cast<const ConstantFunction<double, Domain<Y>> *>(if2)) {
                        ConstantFunction<R, Domain<X, Y>> g(cif1->getConstantValue() * cif2->getConstantValue());
                        h(Interval<X, Y>(lower, upper, closed), &g);
                    }
                    else if (auto lif2 = dynamic_cast<const LinearInterpolatedFunction<double, Domain<Y>> *>(if2)) {
                        LinearInterpolatedFunction<R, Domain<X, Y>> g(lower, upper, lif2->getValue(iyg.getLower()) * cif1->getConstantValue(), lif2->getValue(iyg.getUpper()) * cif1->getConstantValue(), 1);
                        simplifyAndCall(Interval<X, Y>(lower, upper, closed), &g, h);
                    }
                    else
                        throw cRuntimeError("TODO");
                }
                else if (auto lif1 = dynamic_cast<const LinearInterpolatedFunction<R, Domain<X>> *>(if1)) {
                    if (auto cif2 = dynamic_cast<const ConstantFunction<double, Domain<Y>> *>(if2)) {
                        LinearInterpolatedFunction<R, Domain<X, Y>> g(lower, upper, lif1->getValue(ixf.getLower()) * cif2->getConstantValue(), lif1->getValue(ixf.getUpper()) * cif2->getConstantValue(), 0);
                        simplifyAndCall(Interval<X, Y>(lower, upper, closed), &g, h);
                    }
                    else {
                        // QuadraticFunction<double, Domain<X, Y>> g();
                        throw cRuntimeError("TODO");
                    }
                }
                else
                    throw cRuntimeError("TODO");
            });
        });
    }
};

template<typename R, typename D>
class INET_API ShiftFunction : public FunctionBase<R, D>
{
  protected:
    const Ptr<const IFunction<R, D>> f;
    const typename D::P s;

  public:
    ShiftFunction(const Ptr<const IFunction<R, D>>& f, const typename D::P& s) : f(f), s(s) { }

    virtual R getValue(const typename D::P& p) const override {
        return f->getValue(p - s);
    }

    virtual void partition(const typename D::I& i, const std::function<void (const typename D::I&, const IFunction<R, D> *)> g) const override {
        f->partition(typename D::I(i.getLower() - s, i.getUpper() - s, i.getClosed()), [&] (const typename D::I& j, const IFunction<R, D> *jf) {
            if (auto cjf = dynamic_cast<const ConstantFunction<R, D> *>(jf))
                g(typename D::I(j.getLower() + s, j.getUpper() + s, j.getClosed()), jf);
            else if (auto ljf = dynamic_cast<const LinearInterpolatedFunction<R, D> *>(jf)) {
                LinearInterpolatedFunction<R, D> h(j.getLower() + s, j.getUpper() + s, ljf->getValue(j.getLower()), ljf->getValue(j.getUpper()), ljf->getDimension());
                simplifyAndCall(typename D::I(j.getLower() + s, j.getUpper() + s, j.getClosed()), &h, g);
            }
            else {
                ShiftFunction h(const_cast<IFunction<R, D> *>(jf)->shared_from_this(), s);
                simplifyAndCall(typename D::I(j.getLower() + s, j.getUpper() + s, j.getClosed()), &h, g);
            }
        });
    }
};

// TODO:
//template<typename R, typename D>
//class INET_API QuadraticFunction : public Function<R, D>
//{
//  protected:
//    const double a;
//    const double b;
//    const double c;
//
//  public:
//    QuadraticFunction(double a, double b, double c) : a(a), b(b), c(c) { }
//
//    virtual R getValue(const typename D::P& p) const override {
//        return R(0);
//    }
//
//    virtual void partition(const typename D::I& i, const std::function<void (const typename D::I&, const IFunction<R, D> *)> f) const override {
//        throw cRuntimeError("TODO");
//    }
//};

template<typename R, typename D>
class INET_API ReciprocalFunction : public FunctionBase<R, D>
{
  protected:
    // f(x) = (a * x + b) / (c * x + d)
    const double a;
    const double b;
    const double c;
    const double d;
    const int dimension;

  protected:
    virtual double getIntegralFunctionValue(const typename D::P& p) const {
        // https://www.wolframalpha.com/input/?i=integrate+(a+*+x+%2B+b)+%2F+(c+*+x+%2B+d)
        double x = p.get(dimension);
        return (a * c * x + (b * c - a * d) * std::log(d + c * x)) / (c * c);
    }

  public:
    ReciprocalFunction(double a, double b, double c, double d, int dimension) : a(a), b(b), c(c), d(d), dimension(dimension) { }

    virtual int getDimension() const { return dimension; }

    virtual R getValue(const typename D::P& p) const override {
        double x = p.get(dimension);
        return R(a * x + b) / (c * x + d);
    }

    virtual void partition(const typename D::I& i, const std::function<void (const typename D::I&, const IFunction<R, D> *)> f) const override {
        f(i, this);
    }

    virtual R getMin(const typename D::I& i) const override {
        double x = -d / c;
        if (i.getLower().get(dimension) < x && x < i.getUpper().get(dimension))
            return getLowerBoundary<R>();
        else
            return std::min(getValue(i.getLower()), getValue(i.getUpper()));
    }

    virtual R getMax(const typename D::I& i) const override {
        double x = -d / c;
        if (i.getLower().get(dimension) < x && x < i.getUpper().get(dimension))
            return getUpperBoundary<R>();
        else
            return std::max(getValue(i.getLower()), getValue(i.getUpper()));
    }

    virtual R getMean(const typename D::I& i) const override {
        return getIntegral(i) / (i.getUpper().get(dimension) - i.getLower().get(dimension));
    }

    virtual R getIntegral(const typename D::I& i) const override {
        return R(getIntegralFunctionValue(i.getUpper()) - getIntegralFunctionValue(i.getLower()));
    }

    virtual void print(std::ostream& os, const typename D::I& i) const override {
        os << "reciprocal ";
        FunctionBase<R, D>::print(os, i);
    }
};

//template<typename R, typename D>
//class INET_API BireciprocalFunction : public FunctionBase<R, D>
//{
//  protected:
//    // f(x, y) = (a0 + a1 * x + a2 * y + a3 * x * y) / (b0 + b1 * x + b2 * y + b3 * x * y)
//    const double a0;
//    const double a1;
//    const double a2;
//    const double a3;
//    const double b0;
//    const double b1;
//    const double b2;
//    const double b3;
//    const int dimension1;
//    const int dimension2;
//
//  protected:
//    double getIntegral(const typename D::P& p) const {
//        double x = p.get(dimension1);
//        double y = p.get(dimension2);
//        throw cRuntimeError("TODO");
//    }
//
//  public:
//    BireciprocalFunction(double a0, double a1, double a2, double a3, double b0, double b1, double b2, double b3, int dimension1, int dimension2) :
//        a0(a0), a1(a1), a2(a2), a3(a3), b0(b0), b1(b1), b2(b2), b3(b3), dimension1(dimension1), dimension2(dimension2) { }
//
//    virtual R getValue(const typename D::P& p) const override {
//        double x = p.get(dimension1);
//        double y = p.get(dimension2);
//        return R((a0 + a1 * x + a2 * y + a3 * x * y) / (b0 + b1 * x + b2 * y + b3 * x * y));
//    }
//
//    virtual void partition(const typename D::I& i, const std::function<void (const typename D::I&, const IFunction<R, D> *)> f) const override {
//        f(i, this);
//    }
//
//    virtual R getMin(const typename D::I& i) const override {
//        throw cRuntimeError("TODO");
//    }
//
//    virtual R getMax(const typename D::I& i) const override {
//        throw cRuntimeError("TODO");
//    }
//
//    virtual R getMean(const typename D::I& i) const override {
//        throw cRuntimeError("TODO");
//    }
//};

template<typename R, typename D>
class INET_API AdditionFunction : public FunctionBase<R, D>
{
  protected:
    const Ptr<const IFunction<R, D>> f1;
    const Ptr<const IFunction<R, D>> f2;

  public:
    AdditionFunction(const Ptr<const IFunction<R, D>>& f1, const Ptr<const IFunction<R, D>>& f2) : f1(f1), f2(f2) { }

    virtual R getValue(const typename D::P& p) const override {
        return f1->getValue(p) + f2->getValue(p);
    }

    virtual void partition(const typename D::I& i, const std::function<void (const typename D::I&, const IFunction<R, D> *)> f) const override {
        f1->partition(i, [&] (const typename D::I& i1, const IFunction<R, D> *if1) {
            f2->partition(i1, [&] (const typename D::I& i2, const IFunction<R, D> *if2) {
                // TODO: use template specialization for compile time optimization
                if (auto cif1 = dynamic_cast<const ConstantFunction<R, D> *>(if1)) {
                    if (auto cif2 = dynamic_cast<const ConstantFunction<R, D> *>(if2)) {
                        ConstantFunction<R, D> g(cif1->getConstantValue() + cif2->getConstantValue());
                        f(i2, &g);
                    }
                    else if (auto lif2 = dynamic_cast<const LinearInterpolatedFunction<R, D> *>(if2)) {
                        LinearInterpolatedFunction<R, D> g(i2.getLower(), i2.getUpper(), lif2->getValue(i2.getLower()) + cif1->getConstantValue(), lif2->getValue(i2.getUpper()) + cif1->getConstantValue(), lif2->getDimension());
                        simplifyAndCall(i2, &g, f);
                    }
                    else
                        throw cRuntimeError("TODO");
                }
                else if (auto lif1 = dynamic_cast<const LinearInterpolatedFunction<R, D> *>(if1)) {
                    if (auto cif2 = dynamic_cast<const ConstantFunction<R, D> *>(if2)) {
                        LinearInterpolatedFunction<R, D> g(i2.getLower(), i2.getUpper(), lif1->getValue(i2.getLower()) + cif2->getConstantValue(), lif1->getValue(i2.getUpper()) + cif2->getConstantValue(), lif1->getDimension());
                        simplifyAndCall(i2, &g, f);
                    }
                    else if (auto lif2 = dynamic_cast<const LinearInterpolatedFunction<R, D> *>(if2)) {
                        if (lif1->getDimension() == lif2->getDimension()) {
                            LinearInterpolatedFunction<R, D> g(i2.getLower(), i2.getUpper(), lif1->getValue(i2.getLower()) + lif2->getValue(i2.getLower()), lif1->getValue(i2.getUpper()) + lif2->getValue(i2.getUpper()), lif1->getDimension());
                            simplifyAndCall(i2, &g, f);
                        }
                        else {
                            typename D::P lowerLower = D::P::getZero();
                            typename D::P lowerUpper = D::P::getZero();
                            typename D::P upperLower = D::P::getZero();
                            typename D::P upperUpper = D::P::getZero();
                            lowerLower.set(lif1->getDimension(), i1.getLower().get(lif1->getDimension()));
                            lowerUpper.set(lif1->getDimension(), i1.getLower().get(lif1->getDimension()));
                            upperLower.set(lif1->getDimension(), i1.getUpper().get(lif1->getDimension()));
                            upperUpper.set(lif1->getDimension(), i1.getUpper().get(lif1->getDimension()));
                            lowerLower.set(lif2->getDimension(), i2.getLower().get(lif2->getDimension()));
                            lowerUpper.set(lif2->getDimension(), i2.getUpper().get(lif2->getDimension()));
                            upperLower.set(lif2->getDimension(), i2.getLower().get(lif2->getDimension()));
                            upperUpper.set(lif2->getDimension(), i2.getUpper().get(lif2->getDimension()));
                            R rLowerLower = lif1->getValue(lowerLower) + lif2->getValue(lowerLower);
                            R rLowerUpper = lif1->getValue(lowerUpper) + lif2->getValue(lowerUpper);
                            R rUpperLower = lif1->getValue(upperLower) + lif2->getValue(upperLower);
                            R rUpperUpper = lif1->getValue(upperUpper) + lif2->getValue(upperUpper);
                            BilinearInterpolatedFunction<R, D> g(lowerLower, lowerUpper, upperLower, upperUpper, rLowerLower, rLowerUpper, rUpperLower, rUpperUpper, lif1->getDimension(), lif2->getDimension());
                            simplifyAndCall(i2, &g, f);
                        }
                    }
                    else
                        throw cRuntimeError("TODO");
                }
                else
                    throw cRuntimeError("TODO");
            });
        });
    }

    virtual bool isFinite(const typename D::I& i) const override {
        return f1->isFinite(i) & f2->isFinite(i);
    }
};

template<typename R, typename D>
class INET_API SubtractionFunction : public FunctionBase<R, D>
{
  protected:
    const Ptr<const IFunction<R, D>> f1;
    const Ptr<const IFunction<R, D>> f2;

  public:
    SubtractionFunction(const Ptr<const IFunction<R, D>>& f1, const Ptr<const IFunction<R, D>>& f2) : f1(f1), f2(f2) { }

    virtual R getValue(const typename D::P& p) const override {
        return f1->getValue(p) - f2->getValue(p);
    }

    virtual void partition(const typename D::I& i, const std::function<void (const typename D::I&, const IFunction<R, D> *)> f) const override {
        f1->partition(i, [&] (const typename D::I& i1, const IFunction<R, D> *if1) {
            f2->partition(i1, [&] (const typename D::I& i2, const IFunction<R, D> *if2) {
                if (auto cif1 = dynamic_cast<const ConstantFunction<R, D> *>(if1)) {
                    if (auto cif2 = dynamic_cast<const ConstantFunction<R, D> *>(if2)) {
                        ConstantFunction<R, D> g(cif1->getConstantValue() - cif2->getConstantValue());
                        f(i2, &g);
                    }
                    else if (auto lif2 = dynamic_cast<const LinearInterpolatedFunction<R, D> *>(if2)) {
                        LinearInterpolatedFunction<R, D> g(i2.getLower(), i2.getUpper(), lif2->getValue(i2.getLower()) - cif1->getConstantValue(), lif2->getValue(i2.getUpper()) - cif1->getConstantValue(), lif2->getDimension());
                        simplifyAndCall(i2, &g, f);
                    }
                    else
                        throw cRuntimeError("TODO");
                }
                else if (auto lif1 = dynamic_cast<const LinearInterpolatedFunction<R, D> *>(if1)) {
                    if (auto cif2 = dynamic_cast<const ConstantFunction<R, D> *>(if2)) {
                        LinearInterpolatedFunction<R, D> g(i2.getLower(), i2.getUpper(), lif1->getValue(i2.getLower()) - cif2->getConstantValue(), lif1->getValue(i2.getUpper()) - cif2->getConstantValue(), lif1->getDimension());
                        simplifyAndCall(i2, &g, f);
                    }
                    else if (auto lif2 = dynamic_cast<const LinearInterpolatedFunction<R, D> *>(if2)) {
                        if (lif1->getDimension() == lif2->getDimension()) {
                            LinearInterpolatedFunction<R, D> g(i2.getLower(), i2.getUpper(), lif1->getValue(i2.getLower()) - lif2->getValue(i2.getLower()), lif1->getValue(i2.getUpper()) - lif2->getValue(i2.getUpper()), lif1->getDimension());
                            simplifyAndCall(i2, &g, f);
                        }
                        else
                            throw cRuntimeError("TODO");
                    }
                    else
                        throw cRuntimeError("TODO");
                }
                else
                    throw cRuntimeError("TODO");
            });
        });
    }

    virtual bool isFinite(const typename D::I& i) const override {
        return f1->isFinite(i) & f2->isFinite(i);
    }
};

template<typename R, typename D>
class INET_API MultiplicationFunction : public FunctionBase<R, D>
{
  protected:
    const Ptr<const IFunction<R, D>> f1;
    const Ptr<const IFunction<double, D>> f2;

  public:
    MultiplicationFunction(const Ptr<const IFunction<R, D>>& f1, const Ptr<const IFunction<double, D>>& f2) : f1(f1), f2(f2) { }

    virtual const Ptr<const IFunction<R, D>>& getF1() const { return f1; }

    virtual const Ptr<const IFunction<double, D>>& getF2() const { return f2; }

    virtual R getValue(const typename D::P& p) const override {
        return f1->getValue(p) * f2->getValue(p);
    }

    virtual void partition(const typename D::I& i, const std::function<void (const typename D::I&, const IFunction<R, D> *)> f) const override {
        f1->partition(i, [&] (const typename D::I& i1, const IFunction<R, D> *if1) {
            // NOTE: optimization for 0 * x
            if (auto cif1 = dynamic_cast<const ConstantFunction<R, D> *>(if1)) {
                if (toDouble(cif1->getConstantValue()) == 0 && f2->isFinite(i1)) {
                    f(i1, if1);
                    return;
                }
            }
            f2->partition(i1, [&] (const typename D::I& i2, const IFunction<double, D> *if2) {
                if (auto cif1 = dynamic_cast<const ConstantFunction<R, D> *>(if1)) {
                    if (auto cif2 = dynamic_cast<const ConstantFunction<double, D> *>(if2)) {
                        ConstantFunction<R, D> g(cif1->getConstantValue() * cif2->getConstantValue());
                        f(i2, &g);
                    }
                    else if (auto lif2 = dynamic_cast<const LinearInterpolatedFunction<double, D> *>(if2)) {
                        LinearInterpolatedFunction<R, D> g(i2.getLower(), i2.getUpper(), lif2->getValue(i2.getLower()) * cif1->getConstantValue(), lif2->getValue(i2.getUpper()) * cif1->getConstantValue(), lif2->getDimension());
                        simplifyAndCall(i2, &g, f);
                    }
                    else
                        throw cRuntimeError("TODO");
                }
                else if (auto lif1 = dynamic_cast<const LinearInterpolatedFunction<R, D> *>(if1)) {
                    if (auto cif2 = dynamic_cast<const ConstantFunction<double, D> *>(if2)) {
                        LinearInterpolatedFunction<R, D> g(i2.getLower(), i2.getUpper(), lif1->getValue(i2.getLower()) * cif2->getConstantValue(), lif1->getValue(i2.getUpper()) * cif2->getConstantValue(), lif1->getDimension());
                        simplifyAndCall(i2, &g, f);
                    }
                    else if (auto lif2 = dynamic_cast<const LinearInterpolatedFunction<double, D> *>(if2)) {
                        // QuadraticFunction<double, D> g();
                        throw cRuntimeError("TODO");
                    }
                    else
                        throw cRuntimeError("TODO");
                }
                else
                    throw cRuntimeError("TODO");
            });
        });
    }

    virtual bool isFinite(const typename D::I& i) const override {
        return f1->isFinite(i) & f2->isFinite(i);
    }
};

template<typename R, typename D>
class INET_API DivisionFunction : public FunctionBase<double, D>
{
  protected:
    const Ptr<const IFunction<R, D>> f1;
    const Ptr<const IFunction<R, D>> f2;

  public:
    DivisionFunction(const Ptr<const IFunction<R, D>>& f1, const Ptr<const IFunction<R, D>>& f2) : f1(f1), f2(f2) { }

    virtual double getValue(const typename D::P& p) const override {
        return unit(f1->getValue(p) / f2->getValue(p)).get();
    }

    virtual void partition(const typename D::I& i, const std::function<void (const typename D::I&, const IFunction<double, D> *)> f) const override {
        f1->partition(i, [&] (const typename D::I& i1, const IFunction<R, D> *if1) {
            f2->partition(i1, [&] (const typename D::I& i2, const IFunction<R, D> *if2) {
                if (auto cif1 = dynamic_cast<const ConstantFunction<R, D> *>(if1)) {
                    if (auto cif2 = dynamic_cast<const ConstantFunction<R, D> *>(if2)) {
                        ConstantFunction<double, D> g(unit(cif1->getConstantValue() / cif2->getConstantValue()).get());
                        f(i2, &g);
                    }
                    else if (auto lif2 = dynamic_cast<const LinearInterpolatedFunction<R, D> *>(if2)) {
                        ReciprocalFunction<double, D> g(0, toDouble(cif1->getConstantValue()), lif2->getA(), lif2->getB(), lif2->getDimension());
                        simplifyAndCall(i2, &g, f);
                    }
                    else
                        throw cRuntimeError("TODO");
                }
                else if (auto lif1 = dynamic_cast<const LinearInterpolatedFunction<R, D> *>(if1)) {
                    if (auto cif2 = dynamic_cast<const ConstantFunction<R, D> *>(if2)) {
                        LinearInterpolatedFunction<double, D> g(i2.getLower(), i2.getUpper(), unit(lif1->getValue(i2.getLower()) / cif2->getConstantValue()).get(), unit(lif1->getValue(i2.getUpper()) / cif2->getConstantValue()).get(), lif1->getDimension());
                        simplifyAndCall(i2, &g, f);
                    }
                    else if (auto lif2 = dynamic_cast<const LinearInterpolatedFunction<R, D> *>(if2)) {
                        if (lif1->getDimension() == lif2->getDimension()) {
                            ReciprocalFunction<double, D> g(lif1->getA(), lif1->getB(), lif2->getA(), lif2->getB(), lif2->getDimension());
                            simplifyAndCall(i2, &g, f);
                        }
                        else {
                            throw cRuntimeError("TODO");
                            // BireciprocalFunction<double, D> g(...);
                            // simplifyAndCall(i2, &g, f);
                        }
                    }
                    else
                        throw cRuntimeError("TODO");
                }
                else
                    throw cRuntimeError("TODO");
            });
        });
    }

    virtual bool isFinite(const typename D::I& i) const override { return false; }
};

template<typename R, typename D>
class INET_API SumFunction : public FunctionBase<R, D>
{
  protected:
    std::vector<Ptr<const IFunction<R, D>>> fs;

  public:
    SumFunction() { }
    SumFunction(const std::vector<Ptr<const IFunction<R, D>>>& fs) : fs(fs) { }

    const std::vector<Ptr<const IFunction<R, D>>>& getElements() const { return fs; }

    virtual void addElement(const Ptr<const IFunction<R, D>>& f) {
        fs.push_back(f);
    }

    virtual void removeElement(const Ptr<const IFunction<R, D>>& f) {
        fs.erase(std::remove(fs.begin(), fs.end(), f), fs.end());
    }

    virtual R getValue(const typename D::P& p) const override {
        R sum = R(0);
        for (auto f : fs)
            sum += f->getValue(p);
        return sum;
    }

    virtual void partition(const typename D::I& i, const std::function<void (const typename D::I&, const IFunction<R, D> *)> f) const override {
        ConstantFunction<R, D> g(R(0));
        partition(0, i, f, &g);
    }

    virtual void partition(int index, const typename D::I& i, const std::function<void (const typename D::I&, const IFunction<R, D> *)> f, const IFunction<R, D> *g) const {
        if (index == (int)fs.size())
            f(i, g);
        else {
            fs[index]->partition(i, [&] (const typename D::I& i1, const IFunction<R, D> *h) {
                if (auto cg = dynamic_cast<const ConstantFunction<R, D> *>(g)) {
                    if (auto ch = dynamic_cast<const ConstantFunction<R, D> *>(h)) {
                        ConstantFunction<R, D> j(cg->getConstantValue() + ch->getConstantValue());
                        partition(index + 1, i1, f, &j);
                    }
                    else if (auto lh = dynamic_cast<const LinearInterpolatedFunction<R, D> *>(h)) {
                        LinearInterpolatedFunction<R, D> j(i1.getLower(), i1.getUpper(), lh->getValue(i1.getLower()) + cg->getConstantValue(), lh->getValue(i1.getUpper()) + cg->getConstantValue(), lh->getDimension());
                        partition(index + 1, i1, f, &j);
                    }
                    else
                        throw cRuntimeError("TODO");
                }
                else if (auto lg = dynamic_cast<const LinearInterpolatedFunction<R, D> *>(g)) {
                    if (auto ch = dynamic_cast<const ConstantFunction<R, D> *>(h)) {
                        LinearInterpolatedFunction<R, D> j(i1.getLower(), i1.getUpper(), lg->getValue(i1.getLower()) + ch->getConstantValue(), lg->getValue(i1.getUpper()) + ch->getConstantValue(), lg->getDimension());
                        partition(index + 1, i1, f, &j);
                    }
                    else if (auto lh = dynamic_cast<const LinearInterpolatedFunction<R, D> *>(h)) {
                        if (lg->getDimension() == lh->getDimension()) {
                            LinearInterpolatedFunction<R, D> j(i1.getLower(), i1.getUpper(), lg->getValue(i1.getLower()) + lh->getValue(i1.getLower()), lg->getValue(i1.getUpper()) + lh->getValue(i1.getUpper()), lg->getDimension());
                            partition(index + 1, i1, f, &j);
                        }
                        else
                            throw cRuntimeError("TODO");
                    }
                    else
                        throw cRuntimeError("TODO");
                }
                else
                    throw cRuntimeError("TODO");
            });
        }
    }

    virtual bool isFinite(const typename D::I& i) const override {
        for (auto f : fs)
            if (!f->isFinite(i))
                return false;
        return true;
    }
};

template<typename R, typename X, typename Y, int DIMS, typename RI>
class INET_API IntegratedFunction<R, Domain<X, Y>, DIMS, RI, Domain<X>> : public FunctionBase<RI, Domain<X>>
{
    const Ptr<const IFunction<R, Domain<X, Y>>> f;

  public:
    IntegratedFunction(const Ptr<const IFunction<R, Domain<X, Y>>>& f): f(f) { }

    virtual RI getValue(const Point<X>& p) const override {
        Point<X, Y> l1(std::get<0>(p), getLowerBoundary<Y>());
        Point<X, Y> u1(std::get<0>(p), getUpperBoundary<Y>());
        RI ri(0);
        Interval<X, Y> i1(l1, u1, DIMS);
        f->partition(i1, [&] (const Interval<X, Y>& i2, const IFunction<R, Domain<X, Y>> *g) {
            R r = g->getIntegral(i2);
            ri += RI(toDouble(r));
        });
        return ri;
    }

    virtual void partition(const Interval<X>& i, std::function<void (const Interval<X>&, const IFunction<RI, Domain<X>> *)> g) const override {
        Point<X, Y> l1(std::get<0>(i.getLower()), getLowerBoundary<Y>());
        Point<X, Y> u1(std::get<0>(i.getUpper()), getUpperBoundary<Y>());
        Interval<X, Y> i1(l1, u1, (i.getClosed() & 0b1) << 1);
        std::set<X> xs;
        f->partition(i1, [&] (const Interval<X, Y>& i2, const IFunction<R, Domain<X, Y>> *h) {
            xs.insert(std::get<0>(i2.getLower()));
            xs.insert(std::get<0>(i2.getUpper()));
        });
        bool first = true;
        X xLower;
        for (auto it : xs) {
            X xUpper = it;
            if (first)
                first = false;
            else {
                RI ri(0);
                // NOTE: use the lower X for both interval ends, because we assume a constant function and intervals are closed at the lower end
                Point<X, Y> l3(xLower, getLowerBoundary<Y>());
                Point<X, Y> u3(xLower, getUpperBoundary<Y>());
                Interval<X, Y> i3(l3, u3, DIMS);
                f->partition(i3, [&] (const Interval<X, Y>& i4, const IFunction<R, Domain<X, Y>> *h) {
                    if (dynamic_cast<const ConstantFunction<R, Domain<X, Y>> *>(h)) {
                        R r = h->getIntegral(i4);
                        ri += RI(toDouble(r));
                    }
                    else if (auto lh = dynamic_cast<const LinearInterpolatedFunction<R, Domain<X, Y>> *>(h)) {
                        if (lh->getDimension() == 1) {
                            R r = h->getIntegral(i4);
                            ri += RI(toDouble(r));
                        }
                        else
                            throw cRuntimeError("TODO");
                    }
                    else
                        throw cRuntimeError("TODO");
                });
                ConstantFunction<RI, Domain<X>> h(ri);
                Point<X> l5(xLower);
                Point<X> u5(xUpper);
                Interval<X> i5(l5, u5, 0);
                g(i5, &h);
            }
            xLower = xUpper;
        }
    }
};

template<typename R, typename D, int DIMS, typename RI, typename DI>
class INET_API IntegratedFunction : public FunctionBase<RI, DI>
{
    const Ptr<const IFunction<R, D>> f;

  public:
    IntegratedFunction(const Ptr<const IFunction<R, D>>& f): f(f) { }

    virtual RI getValue(const typename DI::P& p) const override {
        auto l1 = D::P::getLowerBoundaries();
        auto u1 = D::P::getUpperBoundaries();
        p.template copyTo<typename D::P, DIMS>(l1);
        p.template copyTo<typename D::P, DIMS>(u1);
        RI ri(0);
        typename D::I i1(l1, u1, DIMS);
        f->partition(i1, [&] (const typename D::I& i2, const IFunction<R, D> *g) {
            R r = g->getIntegral(i2);
            ri += RI(toDouble(r));
        });
        return ri;
    }

    virtual void partition(const typename DI::I& i, std::function<void (const typename DI::I&, const IFunction<RI, DI> *)> g) const override {
        throw cRuntimeError("TODO");
    }
};

template<typename R, typename D, int DIMENSION, typename X>
class INET_API ApproximatedFunction : public FunctionBase<R, D>
{
  protected:
    const X lower;
    const X upper;
    const X step;
    const IInterpolator<X, R> *interpolator;
    const Ptr<const IFunction<R, D>> f;

  public:
    ApproximatedFunction(X lower, X upper, X step, const IInterpolator<X, R> *interpolator, const Ptr<const IFunction<R, D>>& f): lower(lower), upper(upper), step(step), interpolator(interpolator), f(f) { }

    virtual R getValue(const typename D::P& p) const override {
        X x = std::get<DIMENSION>(p);
        if (x < lower) {
            typename D::P p1 = p;
            std::get<DIMENSION>(p1) = lower;
            return f->getValue(p1);
        }
        else if (x > upper) {
            typename D::P p1 = p;
            std::get<DIMENSION>(p1) = upper;
            return f->getValue(p1);
        }
        else {
            X x1 = std::max(lower, step * floor(toDouble(x / step)));
            X x2 = std::min(upper, step * ceil(toDouble(x / step)));
            typename D::P p1 = p;
            std::get<DIMENSION>(p1) = x1;
            typename D::P p2 = p;
            std::get<DIMENSION>(p2) = x2;
            R r1 = f->getValue(p1);
            R r2 = f->getValue(p2);
            return interpolator->getValue(x1, r1, x2, r2, x);
        }
    }

    virtual void partition(const typename D::I& i, std::function<void (const typename D::I&, const IFunction<R, D> *)> g) const override {
        const auto& lower = i.getLower();
        const auto& upper = i.getUpper();
        X min = step * floor(toDouble(std::get<DIMENSION>(lower) / step));
        X max = step * ceil(toDouble(std::get<DIMENSION>(upper) / step));
        for (X x = min; x < max; x += step) {
            X x1 = std::max(std::get<DIMENSION>(lower), x);
            X x2 = std::min(std::get<DIMENSION>(upper), x + step);
            typename D::P p1 = lower;
            std::get<DIMENSION>(p1) = x1;
            typename D::P p2 = upper;
            std::get<DIMENSION>(p2) = x2;
            R r1 = f->getValue(p1);
            R r2 = f->getValue(p2);
            if (dynamic_cast<const LinearInterpolator<X, R> *>(interpolator)) {
                LinearInterpolatedFunction<R, D> h(p1, p2, r1, r2, DIMENSION);
                typename D::I i1(p1, p2, i.getClosed());
                simplifyAndCall(i1, &h, g);
            }
            else if (dynamic_cast<const CenterInterpolator<X, R> *>(interpolator)) {
                ConstantFunction<R, D> h(interpolator->getValue(x1, r1, x2, r2, (x1 + x2) / 2));
                typename D::I i1(p1, p2, i.getClosed());
                simplifyAndCall(i1, &h, g);
            }
            else
                throw cRuntimeError("TODO");
        }
    }

    virtual bool isFinite(const typename D::I& i) const override {
        return f->isFinite(i);
    }
};

template<typename R, typename X, typename Y>
class INET_API ExtrudedFunction : public FunctionBase<R, Domain<X, Y>>
{
  protected:
    const Ptr<const IFunction<R, Domain<Y>>> f;

  public:
    ExtrudedFunction(const Ptr<const IFunction<R, Domain<Y>>>& f) : f(f) { }

    virtual R getValue(const Point<X, Y>& p) const override {
        return f->getValue(Point<Y>(std::get<1>(p)));
    }

    virtual void partition(const Interval<X, Y>& i, std::function<void (const Interval<X, Y>&, const IFunction<R, Domain<X, Y>> *)> g) const override {
        Interval<Y> i1(Point<Y>(std::get<1>(i.getLower())), Point<Y>(std::get<1>(i.getUpper())), i.getClosed() & 0b01);
        f->partition(i1, [&] (const Interval<Y>& i2, const IFunction<R, Domain<Y>> *h) {
            Point<X, Y> lower(std::get<0>(i.getLower()), std::get<0>(i2.getLower()));
            Point<X, Y> upper(std::get<0>(i.getUpper()), std::get<0>(i2.getUpper()));
            Interval<X, Y> i3(lower, upper, (i.getClosed() & 0b10) | i2.getClosed());
            if (auto ch = dynamic_cast<const ConstantFunction<R, Domain<Y>> *>(h)) {
                ConstantFunction<R, Domain<X, Y>> j(ch->getConstantValue());
                g(i3, &j);
            }
            else if (auto lh = dynamic_cast<const LinearInterpolatedFunction<R, Domain<Y>> *>(h)) {
                Point<X, Y> lower(std::get<0>(i.getLower()), std::get<0>(lh->getLower()));
                Point<X, Y> upper(std::get<0>(i.getUpper()), std::get<0>(lh->getUpper()));
                LinearInterpolatedFunction<R, Domain<X, Y>> j(lower, upper, lh->getRLower(), lh->getRUpper(), 1);
                g(i3, &j);
            }
            else
                throw cRuntimeError("TODO");
        });
    }

    virtual bool isFinite(const Interval<X, Y>& i) const override {
        Interval<Y> i1(Point<Y>(std::get<1>(i.getLower())), Point<Y>(std::get<1>(i.getUpper())), i.getClosed() & 0b01);
        return f->isFinite(i1);
    }
};

template<typename R, typename D>
class INET_API MemoizedFunction : public FunctionBase<R, D>
{
  protected:
    const Ptr<const IFunction<R, D>> f;

  public:
    MemoizedFunction(const Ptr<const IFunction<R, D>>& f) : f(f) {
        f->partition(f->getDomain(), [] (const typename D::I& i, const IFunction<R, D> *g) {
            // TODO: store all interval function pairs in a domain subdivision tree structure
            throw cRuntimeError("TODO");
        });
    }

    virtual R getValue(const typename D::P& p) const override {
        f->getValue(p);
    }

    virtual void partition(const typename D::I& i, std::function<void (const typename D::I&, const IFunction<R, D> *)> g) const override {
        // TODO: search in domain subdivision tree structure
        throw cRuntimeError("TODO");
    }
};

template<typename R, typename D>
void simplifyAndCall(const typename D::I& i, const IFunction<R, D> *f, const std::function<void (const typename D::I&, const IFunction<R, D> *)> g) {
    g(i, f);
}

template<typename R, typename D>
void simplifyAndCall(const typename D::I& i, const LinearInterpolatedFunction<R, D> *f, const std::function<void (const typename D::I&, const IFunction<R, D> *)> g) {
    if (f->getRLower() == f->getRUpper()) {
        ConstantFunction<R, D> h(f->getRLower());
        g(i, &h);
    }
    else
        g(i, f);
}

template<typename R, typename D>
void simplifyAndCall(const typename D::I& i, const BilinearInterpolatedFunction<R, D> *f, const std::function<void (const typename D::I&, const IFunction<R, D> *)> g) {
    if (f->getRLowerLower() == f->getRLowerUpper() && f->getRLowerLower() == f->getRUpperLower() && f->getRLowerLower() == f->getRUpperUpper()) {
        ConstantFunction<R, D> h(f->getRLowerLower());
        g(i, &h);
    }
    // TODO: one dimensional linear functions?
    else
        g(i, f);
}

} // namespace math

} // namespace inet

#endif // #ifndef __INET_MATH_FUNCTIONS_H_


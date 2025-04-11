import { Link } from "react-router-dom";
import Navbar from "../../components/Navbar";
import Footer from "./Footer";
import ReminderPopup from "./ReminderPopup";


function Home() {
    return (
        <>
            <Navbar />
            <ReminderPopup/>
            <section className="bg-white dark:bg-gray-900">
                <div className="grid max-w-screen-xl px-4 py-8 mx-auto lg:gap-8 xl:gap-0 lg:py-16 lg:grid-cols-12">
                    <div className="mr-auto place-self-center lg:col-span-7">
                        <h1 className="max-w-2xl mb-4 text-4xl font-extrabold tracking-tight leading-none md:text-5xl xl:text-6xl dark:text-white">
                            Your Journey to Better Mental Health Starts Here            <a className="absolute -top-2 -right-2 bg-red-600 z-50 text-white text-xs px-2 py-0.5 rounded-full"/>
                        </h1>
                        <p className="max-w-2xl mb-6 font-light text-gray-500 lg:mb-8 md:text-lg lg:text-xl dark:text-gray-400">
                            From checkout to global sales tax compliance, companies around the world use Flowbite to simplify their payment stack.
                        </p>
                        <Link to={"/login"}
                            
                            className="bg-primaryBg inline-flex items-center justify-center px-5 py-3 mr-3 text-base font-medium text-white rounded-lg hover:bg-green-600 focus:ring-4 focus:ring-green-300 dark:focus:ring-green-900"
                        >
                            Login to Continue
                            <svg
                                className="w-5 h-5 ml-2 -mr-1"
                                fill="currentColor"
                                viewBox="0 0 20 20"
                                xmlns="http://www.w3.org/2000/svg"
                            >
                                <path
                                    fillRule="evenodd"
                                    d="M10.293 3.293a1 1 0 011.414 0l6 6a1 1 0 010 1.414l-6 6a1 1 0 01-1.414-1.414L14.586 11H3a1 1 0 110-2h11.586l-4.293-4.293a1 1 0 010-1.414z"
                                    clipRule="evenodd"
                                ></path>
                            </svg>
                        </Link>
                        <a
                            href="#"
                            className="inline-flex items-center justify-center px-5 py-3 text-base font-medium text-gray-900 border border-gray-300 rounded-lg hover:bg-gray-100 focus:ring-4 focus:ring-gray-100 dark:text-white dark:border-gray-700 dark:hover:bg-gray-700 dark:focus:ring-gray-800"
                        >
                            Learn More
                        </a>
                    </div>
                    <div className="flex justify-center mt-6 lg:mt-0 lg:col-span-5">
                        <img
                            src="https://img.freepik.com/free-vector/psychotherapy-abstract-concept-illustration-non-pharmacological-intervention-verbal-counseling-psychotherapy-service-behavioral-cognitive-therapy-private-session_335657-554.jpg?t=st=1741507248~exp=1741510848~hmac=c5bb188f754101ae992f38865788458248181425b9d6a072ca2e28174ad2c2c1&w=740"
                            alt="mockup"
                            className="w-full max-w-xs sm:max-w-sm md:max-w-md lg:max-w-lg"
                        />
                    </div>
                </div>
            </section>
            <Footer/>
        </>
    );
}

export default Home;
